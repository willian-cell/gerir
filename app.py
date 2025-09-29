import os
from datetime import datetime, date, time
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import re

# =========================
# Configuração básica
# =========================
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__, instance_relative_config=True)
app.config["SECRET_KEY"] = "change-this-in-production"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "instance", "gerir.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_DIR
os.makedirs(os.path.join(BASE_DIR, "instance"), exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# =========================
# Constantes de papel
# =========================
ROLE_ADMIN = "ADMIN"
ROLE_OL = "OL"
ROLE_ENTREGADOR = "ENTREGADOR"
ROLE_CHOICES = [ROLE_ADMIN, ROLE_OL, ROLE_ENTREGADOR]

# =========================
# Modelos
# =========================
class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    # =======================
    # Dados pessoais
    # =======================
    foto = db.Column(db.String(255))
    nome = db.Column(db.String(120), nullable=False)
    cpf = db.Column(db.String(20), unique=True, nullable=False)
    telefone = db.Column(db.String(30))
    email = db.Column(db.String(120), unique=True, nullable=False)
    data_nascimento = db.Column(db.String(10))   # formato dd/mm/aaaa (simples)
    estado_civil = db.Column(db.String(30))
    estado = db.Column(db.String(2))
    cidade = db.Column(db.String(80))
    endereco = db.Column(db.String(160))
    cep = db.Column(db.String(20))

    # =======================
    # Controle de acesso
    # =======================
    role = db.Column(db.String(20), nullable=False, default="ENTREGADOR")  # 🔹 Mantém padrão entregador
    password_hash = db.Column(db.String(255), nullable=False)

    # =======================
    # Documentos
    # =======================
    documentos = db.Column(db.Text)  # exemplo: "rg.pdf;cnp.pdf"

    # =======================
    # Auditoria
    # =======================
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)  # 🔹 Novo campo: data de criação
    atualizado_em = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)  
    # 🔹 Novo campo: atualiza sempre que salvar

    # =======================
    # Relacionamentos
    # =======================
    agendas = db.relationship(
        "Agenda", back_populates="entregador",
        cascade="all, delete-orphan"   # 🔹 Agora sincronizado com o modelo Agenda
    )

    # =======================
    # Métodos utilitários
    # =======================
    def set_password(self, raw):
        """Criptografa a senha antes de salvar."""
        self.password_hash = bcrypt.generate_password_hash(raw).decode("utf-8")

    def check_password(self, raw):
        """Valida a senha do usuário."""
        return bcrypt.check_password_hash(self.password_hash, raw)

    def get_id(self):
        """Compatibilidade com Flask-Login."""
        return str(self.id)

    def __repr__(self):
        """Representação amigável no console."""
        return f"<User {self.id} - {self.nome} ({self.role})>"



class Entrega(db.Model):
    __tablename__ = "entregas"
    id = db.Column(db.Integer, primary_key=True)
    entregador_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    data = db.Column(db.Date, nullable=False, default=date.today)
    descricao = db.Column(db.String(255))
    valor = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(30), default="PENDENTE")  # PENDENTE | CONCLUIDA

    entregador = db.relationship("User", backref="entregas")


class Agenda(db.Model):
    __tablename__ = "agendas"

    id = db.Column(db.Integer, primary_key=True)
    entregador_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    dia = db.Column(db.Date, nullable=False)
    hora_inicio = db.Column(db.Time, nullable=False)
    hora_fim = db.Column(db.Time, nullable=False)
    regiao = db.Column(db.String(120), nullable=False)

    # Novo campo para controle de status
    status = db.Column(db.String(10), default="ativo", nullable=False)

    # Auditoria
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)

    # Relacionamento bidirecional
    entregador = db.relationship("User", back_populates="agendas")

    def __repr__(self):
        return f"<Agenda {self.id} - {self.entregador.nome} - {self.dia} ({self.status})>"


# =========================
# Carregador do Login
# =========================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# =========================
# Helpers de autorização
# =========================
def require_roles(*roles):
    def wrapper(fn):
        def inner(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role not in roles:
                abort(403)
            return fn(*args, **kwargs)
        inner.__name__ = fn.__name__
        return inner
    return wrapper

def can_manage_user(target: User):
    """
    Regras:
    - Admin pode tudo.
    - OL pode criar/editar/excluir APENAS ENTREGADORES.
    - Entregador só pode ver/editar o próprio perfil (senha, docs, agenda).
    """
    if current_user.role == ROLE_ADMIN:
        return True
    if current_user.role == ROLE_OL:
        return target.role == ROLE_ENTREGADOR
    if current_user.role == ROLE_ENTREGADOR:
        return target.id == current_user.id
    return False

# =========================
# CLI de inicialização
# =========================
@app.cli.command("init-db")
def init_db():
    """flask init-db"""
    db.create_all()
    # cria admin padrão se não existir
    if not User.query.filter_by(email="admin@gerir.local").first():
        admin = User(
            nome="Administrador",
            cpf="000.000.000-00",
            telefone="(61) 0000-0000",
            email="admin@gerir.local",
            role=ROLE_ADMIN
        )
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()
        print("Admin padrão criado: admin@gerir.local / admin123")
    else:
        print("Banco já inicializado.")

# =========================
# Autenticação
# =========================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Login efetuado.", "success")
            return redirect(url_for("home"))
        flash("Credenciais inválidas.", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Sessão encerrada.", "info")
    return redirect(url_for("login"))

# =========================
# Home -> redireciona por papel
# =========================
@app.route("/")
@login_required
def home():
    if current_user.role == ROLE_ADMIN:
        return redirect(url_for("dashboard_admin"))
    if current_user.role == ROLE_OL:
        return redirect(url_for("dashboard_ol"))
    return redirect(url_for("dashboard_entregador"))

# =========================
# Dashboards
# =========================
@app.route("/admin")
@login_required
@require_roles(ROLE_ADMIN)
def dashboard_admin():
    total_users = User.query.count()
    total_ol = User.query.filter_by(role=ROLE_OL).count()
    total_entregadores = User.query.filter_by(role=ROLE_ENTREGADOR).count()

    # alguns KPIs simples
    total_entregas = Entrega.query.count()
    total_receber = db.session.query(db.func.sum(Entrega.valor))\
                              .filter(Entrega.status == "CONCLUIDA").scalar() or 0.0

    return render_template(
        "dashboard_admin.html",
        total_users=total_users,
        total_ol=total_ol,
        total_entregadores=total_entregadores,
        total_entregas=total_entregas,
        total_receber=total_receber
    )

@app.route("/ol")
@login_required
@require_roles(ROLE_OL)
def dashboard_ol():
    # OL: ver total de entregadores, entregas etc.
    total_entregadores = User.query.filter_by(role=ROLE_ENTREGADOR).count()
    total_entregas = Entrega.query.count()
    concluidas = Entrega.query.filter_by(status="CONCLUIDA").count()
    pendentes = total_entregas - concluidas
    return render_template(
        "dashboard_ol.html",
        total_entregadores=total_entregadores,
        total_entregas=total_entregas,
        concluidas=concluidas,
        pendentes=pendentes
    )

@app.route("/entregador")
@login_required
@require_roles(ROLE_ENTREGADOR)
def dashboard_entregador():
    minhas_entregas = Entrega.query.filter_by(entregador_id=current_user.id).all()
    total = len(minhas_entregas)
    concluidas = len([e for e in minhas_entregas if e.status == "CONCLUIDA"])
    pendentes = total - concluidas
    total_receber = sum(e.valor for e in minhas_entregas if e.status == "CONCLUIDA")
    return render_template(
        "dashboard_entregador.html",
        total=total, concluidas=concluidas, pendentes=pendentes, total_receber=total_receber
    )

# =========================
# Gestão de Usuários (Admin e OL)
# =========================
@app.route("/users")
@login_required
def users_list():
    if current_user.role == ROLE_ADMIN:
        q = User.query.order_by(User.role.desc(), User.nome.asc()).all()
    elif current_user.role == ROLE_OL:
        # OL vê todos os ENTREGADORES
        q = User.query.filter_by(role=ROLE_ENTREGADOR).order_by(User.nome.asc()).all()
    else:
        # ENTREGADOR vê só ele
        q = [current_user]
    return render_template("users_list.html", users=q)

@app.route("/users/new", methods=["GET", "POST"])
@login_required
def users_new():
    # Admin pode criar qualquer papel
    # OL pode criar apenas ENTREGADOR
    if request.method == "POST":
        role = request.form.get("role", ROLE_ENTREGADOR)
        if current_user.role == ROLE_OL and role != ROLE_ENTREGADOR:
            flash("Operador Logístico só pode cadastrar ENTREGADORES.", "warning")
            return redirect(url_for("users_new"))

        nome = request.form.get("nome", "").strip().title()
        cpf = re.sub(r'\D', '', request.form.get("cpf", ""))
        telefone = re.sub(r'\D', '', request.form.get("telefone", ""))
        email = request.form.get("email", "").strip().lower()

        # Tenta converter data para objeto date
        data_nascimento_str = request.form.get("data_nascimento", "")
        try:
            data_nascimento = datetime.strptime(data_nascimento_str, "%d/%m/%Y").strftime("%d/%m/%Y")
        except ValueError:
            data_nascimento = None

        estado_civil = request.form.get("estado_civil")
        estado = request.form.get("estado", "").strip().upper()[:2]
        cidade = request.form.get("cidade", "").strip().title()
        endereco = request.form.get("endereco", "").strip().title()
        cep = re.sub(r'\D', '', request.form.get("cep", ""))

        u = User(
            nome=request.form.get("nome"),
            cpf=request.form.get("cpf"),
            telefone=request.form.get("telefone"),
            email=request.form.get("email"),
            data_nascimento=request.form.get("data_nascimento"),
            estado_civil=request.form.get("estado_civil"),
            estado=request.form.get("estado"),
            cidade=request.form.get("cidade"),
            endereco=request.form.get("endereco"),
            cep=request.form.get("cep"),
            role=role
        )
        senha = request.form.get("senha", "123456")
        u.set_password(senha)

        # upload simples de foto
        foto = request.files.get("foto")
        if foto and foto.filename:
            fname = secure_filename(foto.filename)
            path = os.path.join(app.config["UPLOAD_FOLDER"], fname)
            foto.save(path)
            u.foto = fname

        db.session.add(u)
        db.session.commit()
        flash("Usuário cadastrado.", "success")
        return redirect(url_for("users_list"))

    return render_template("user_form.html", user=None, roles=ROLE_CHOICES)


@app.route("/users/<int:user_id>/view")
@login_required
def users_view(user_id):
    u = User.query.get_or_404(user_id)
    if not can_manage_user(u):
        abort(403)
    return render_template("user_view.html", user=u)



@app.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
def users_edit(user_id):
    u = User.query.get_or_404(user_id)
    if not can_manage_user(u):
        abort(403)

    if request.method == "POST":
        # regras de papel:
        new_role = request.form.get("role", u.role)
        if current_user.role == ROLE_OL and u.role != ROLE_ENTREGADOR:
            abort(403)
        if current_user.role == ROLE_OL and new_role != ROLE_ENTREGADOR:
            flash("Operador Logístico não pode alterar o papel para outro que não seja ENTREGADOR.", "warning")
            new_role = ROLE_ENTREGADOR

        u.nome = request.form.get("nome", "").strip().title()
        u.cpf = re.sub(r'\D', '', request.form.get("cpf", ""))
        u.telefone = re.sub(r'\D', '', request.form.get("telefone", ""))
        u.email = request.form.get("email", "").strip().lower()

        data_nascimento_str = request.form.get("data_nascimento", "")
        try:
            u.data_nascimento = datetime.strptime(data_nascimento_str, "%d/%m/%Y").strftime("%d/%m/%Y")
        except ValueError:
            u.data_nascimento = None

        u.estado_civil = request.form.get("estado_civil")
        u.estado = request.form.get("estado", "").strip().upper()[:2]
        u.cidade = request.form.get("cidade", "").strip().title()
        u.endereco = request.form.get("endereco", "").strip().title()
        u.cep = re.sub(r'\D', '', request.form.get("cep", ""))
        u.role = new_role

        # nova foto?
        foto = request.files.get("foto")
        if foto and foto.filename:
            fname = secure_filename(foto.filename)
            path = os.path.join(app.config["UPLOAD_FOLDER"], fname)
            foto.save(path)
            u.foto = fname

        # reset de senha (opcional)
        nova_senha = request.form.get("senha")
        if nova_senha:
            u.set_password(nova_senha)

        db.session.commit()
        flash("Dados atualizados.", "success")
        return redirect(url_for("users_list"))

    return render_template("user_form.html", user=u, roles=ROLE_CHOICES)

@app.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
def users_delete(user_id):
    u = User.query.get_or_404(user_id)
    if not can_manage_user(u):
        abort(403)
    # impedimos deletar a si próprio se for o único admin (simples)
    if u.role == ROLE_ADMIN and current_user.id == u.id:
        admins = User.query.filter_by(role=ROLE_ADMIN).count()
        if admins <= 1:
            flash("Não é possível excluir o único administrador.", "danger")
            return redirect(url_for("users_list"))

    db.session.delete(u)
    db.session.commit()
    flash("Usuário excluído.", "info")
    return redirect(url_for("users_list"))

# =========================
# Perfil do Entregador (autoatendimento)
# =========================
@app.route("/profile", methods=["GET", "POST"])
@login_required
@require_roles(ROLE_ENTREGADOR)
def profile():
    u = current_user
    if request.method == "POST":
        # atualização de dados pessoais próprios (limitado)
        u.telefone = request.form.get("telefone")
        u.endereco = request.form.get("endereco")
        u.cidade = request.form.get("cidade")
        u.estado = request.form.get("estado")
        u.cep = request.form.get("cep")

        # envio de documentos (múltiplos)
        files = request.files.getlist("documentos")
        stored = [d for d in (u.documentos or "").split(";") if d]
        for f in files:
            if f and f.filename:
                fname = secure_filename(f"{u.id}_{f.filename}")
                f.save(os.path.join(app.config["UPLOAD_FOLDER"], fname))
                stored.append(fname)
        u.documentos = ";".join(stored)

        # redefinir a própria senha
        nova = request.form.get("nova_senha")
        if nova:
            u.set_password(nova)

        db.session.commit()
        flash("Perfil atualizado.", "success")
        return redirect(url_for("profile"))

    docs = [d for d in (u.documentos or "").split(";") if d]
    return render_template("profile.html", user=u, docs=docs)

@app.route("/uploads/<path:filename>")
@login_required
def uploaded_file(filename):
    # Admin e OL podem ver tudo; Entregador só vê seus próprios docs/fotos
    if current_user.role == ROLE_ENTREGADOR:
        if not (filename.startswith(f"{current_user.id}_") or filename == current_user.foto):
            abort(403)
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=False)

# =========================
# Entregas (listagem e CRUD)
# =========================
@app.route("/entregas")
@login_required
def entregas_list():
    users = None  # só usado por ADMIN/OL
    total_receber = None

    if current_user.role in [ROLE_ADMIN, ROLE_OL]:
        # Admin e OL veem todas as entregas
        entregas = Entrega.query.order_by(Entrega.data.desc()).all()
        # Lista de entregadores para o <select> do formulário
        users = User.query.filter_by(role=ROLE_ENTREGADOR).order_by(User.nome.asc()).all()

    elif current_user.role == ROLE_ENTREGADOR:
        # Entregador só vê as próprias entregas
        entregas = Entrega.query.filter_by(entregador_id=current_user.id).order_by(Entrega.data.desc()).all()
        # Total a receber (somente entregas concluídas)
        total_receber = (
            db.session.query(db.func.sum(Entrega.valor))
            .filter_by(entregador_id=current_user.id, status="CONCLUIDA")
            .scalar() or 0.0
        )

    else:
        abort(403)  # caso algum papel inválido tente acessar

    return render_template(
        "entregas_list.html",
        entregas=entregas,
        users=users,
        total_receber=total_receber
    )

@app.route("/entregas/new", methods=["POST"])
@login_required
def entregas_new():
    # Admin e OL podem lançar para qualquer entregador; entregador lança só para si mesmo
    entregador_id = int(request.form.get("entregador_id", current_user.id))
    if current_user.role == ROLE_ENTREGADOR and entregador_id != current_user.id:
        abort(403)
    data_str = request.form.get("data") or date.today().isoformat()
    descricao = request.form.get("descricao") or ""
    valor = float(request.form.get("valor") or 0)
    status = request.form.get("status") or "PENDENTE"

    e = Entrega(
        entregador_id=entregador_id,
        data=datetime.fromisoformat(data_str).date(),
        descricao=descricao,
        valor=valor,
        status=status
    )
    db.session.add(e)
    db.session.commit()
    flash("Entrega cadastrada.", "success")
    return redirect(url_for("entregas_list"))

@app.route("/entregas/<int:entrega_id>/update", methods=["POST"])
@login_required
def entregas_update(entrega_id):
    e = Entrega.query.get_or_404(entrega_id)
    # Permissões
    if current_user.role == ROLE_ENTREGADOR and e.entregador_id != current_user.id:
        abort(403)
    if current_user.role == ROLE_OL and e.entregador.role != ROLE_ENTREGADOR:
        abort(403)

    e.data = datetime.fromisoformat(request.form.get("data")).date()
    e.descricao = request.form.get("descricao")
    e.valor = float(request.form.get("valor") or 0)
    e.status = request.form.get("status") or "PENDENTE"
    db.session.commit()
    flash("Entrega atualizada.", "success")
    return redirect(url_for("entregas_list"))

@app.route("/entregas/<int:entrega_id>/delete", methods=["POST"])
@login_required
def entregas_delete(entrega_id):
    e = Entrega.query.get_or_404(entrega_id)
    if current_user.role == ROLE_ENTREGADOR and e.entregador_id != current_user.id:
        abort(403)
    if current_user.role == ROLE_OL and e.entregador.role != ROLE_ENTREGADOR:
        abort(403)

    db.session.delete(e)
    db.session.commit()
    flash("Entrega excluída.", "info")
    return redirect(url_for("entregas_list"))

# =========================
# Agenda (entregador escolhe dias/horários/região)
# =========================
@app.route("/agenda")
@login_required
def agenda_list():
    query = Agenda.query.join(User)

    # Se for entregador, só mostra suas agendas
    if current_user.role == ROLE_ENTREGADOR:
        query = query.filter(Agenda.entregador_id == current_user.id)
        entregadores = None
    else:
        entregadores = User.query.filter_by(role=ROLE_ENTREGADOR).order_by(User.nome).all()

    # Filtro por ID
    if request.args.get("id"):
        try:
            query = query.filter(Agenda.id == int(request.args["id"]))
        except ValueError:
            pass  # ignora se não for número

    # Filtro por Nome
    if request.args.get("nome"):
        nome = request.args["nome"].strip()
        query = query.filter(User.nome.ilike(f"%{nome}%"))

    # Filtro por Status
    if request.args.get("status"):
        query = query.filter(Agenda.status == request.args["status"])

    # Filtro por Data
    if request.args.get("data"):
        try:
            data = datetime.fromisoformat(request.args["data"]).date()
            query = query.filter(Agenda.dia == data)
        except ValueError:
            pass

    agendas = query.order_by(Agenda.dia.desc()).all()

    return render_template("agenda_list.html", agendas=agendas, entregadores=entregadores)


@app.route("/agenda/new", methods=["POST"])
@login_required
def agenda_new():
    if current_user.role == ROLE_ENTREGADOR:
        entregador_id = current_user.id
    else:
        entregador_id = int(request.form.get("entregador_id"))

    if current_user.role == ROLE_OL:
        ent = User.query.get_or_404(entregador_id)
        if ent.role != ROLE_ENTREGADOR:
            abort(403)

    dia = datetime.fromisoformat(request.form.get("dia")).date()
    hora_inicio = time.fromisoformat(request.form.get("hora_inicio"))
    hora_fim = time.fromisoformat(request.form.get("hora_fim"))
    regiao = request.form.get("regiao")
    status = request.form.get("status", "ativo")
    ag = Agenda(
        entregador_id=entregador_id,
        dia=dia,
        hora_inicio=hora_inicio,
        hora_fim=hora_fim,
        regiao=regiao,
        status=status
    )

    db.session.add(ag)
    db.session.commit()
    flash("Agenda registrada.", "success")
    return redirect(url_for("agenda_list"))

@app.route("/agenda/<int:agenda_id>/delete", methods=["POST"])
@login_required
def agenda_delete(agenda_id):
    ag = Agenda.query.get_or_404(agenda_id)
    if current_user.role == ROLE_ENTREGADOR and ag.entregador_id != current_user.id:
        abort(403)
    if current_user.role == ROLE_OL and ag.entregador.role != ROLE_ENTREGADOR:
        abort(403)
    db.session.delete(ag)
    db.session.commit()
    flash("Agenda removida.", "info")
    return redirect(url_for("agenda_list"))

@app.route("/agenda/<int:agenda_id>/toggle", methods=["POST"])
@login_required
def agenda_toggle(agenda_id):
    ag = Agenda.query.get_or_404(agenda_id)

    # Permissões
    if current_user.role == ROLE_ENTREGADOR and ag.entregador_id != current_user.id:
        abort(403)
    if current_user.role == ROLE_OL and ag.entregador.role != ROLE_ENTREGADOR:
        abort(403)

    # Alternar status
    ag.status = "ativo" if ag.status == "inativo" else "inativo"
    db.session.commit()
    flash("Status atualizado com sucesso.", "info")

    return redirect(url_for("agenda_list"))


# =========================
# Executar
# =========================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=True)
