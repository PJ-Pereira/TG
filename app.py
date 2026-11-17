from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
from flask_wtf.csrf import CSRFProtect, CSRFError
from werkzeug.security import check_password_hash as werkzeug_check_hash
from datetime import datetime, date, timedelta
from functools import wraps
from urllib.parse import urlparse
from sqlalchemy import func, inspect, text
from dotenv import load_dotenv
import bcrypt
import click
import os
import re
import secrets
import smtplib
import threading
import time
from email.message import EmailMessage

# Configurações sensíveis ficam no arquivo .env (fora do código) – ver .env.example
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, '.env'))

app = Flask(__name__)


def _chave_secreta():
    """SECRET_KEY do .env; se não houver, gera uma aleatória e guarda em instance/ (fora do código)."""
    chave = os.environ.get('SECRET_KEY')
    if chave:
        return chave
    os.makedirs(app.instance_path, exist_ok=True)
    arq = os.path.join(app.instance_path, 'secret_key')
    if not os.path.exists(arq):
        with open(arq, 'w') as f:
            f.write(secrets.token_hex(32))
    with open(arq) as f:
        return f.read().strip()


MINUTOS_INATIVIDADE = 10   # RNF02

app.config['SECRET_KEY'] = _chave_secreta()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sei_digital.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Cookies de sessão: inacessíveis via JavaScript, não enviados por outros sites,
# e só por HTTPS quando SESSION_COOKIE_SECURE=1 no .env (servidor em produção)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE') == '1'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=MINUTOS_INATIVIDADE)
app.config['WTF_CSRF_TIME_LIMIT'] = None   # o token vale enquanto a sessão for válida

db = SQLAlchemy(app)
csrf = CSRFProtect(app)   # tokens CSRF em todos os formulários POST
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Por favor, faça login para acessar esta página.'
login_manager.login_message_category = 'warning'
login_manager.session_protection = 'strong'


# ─────────────────────────────────────────────
# MODELS  (seguem o DER do documento – Figura 3)
#
#   Funcionário (usuario) 1 ──── 0..n  Item de Histórico (relatorio)
#   Aluno                 1 ──── 0..n  Item de Histórico (relatorio)
#   Aluno                 1 ──── 0..1  Diagnóstico
#   Diagnóstico           n ──── n     Neurodivergência   (tabela "possui")
# ─────────────────────────────────────────────

possui = db.Table(
    'possui',
    db.Column('diagnostico_id', db.Integer,
              db.ForeignKey('diagnostico.id', ondelete='CASCADE'), primary_key=True),
    db.Column('neurodivergencia_id', db.Integer,
              db.ForeignKey('neurodivergencia.id', ondelete='CASCADE'), primary_key=True),
)


class Usuario(UserMixin, db.Model):
    """Entidade Funcionário do DER."""
    __tablename__ = 'usuario'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    cargo = db.Column(db.String(50))
    email = db.Column(db.String(120), unique=True, nullable=False)
    senha_hash = db.Column(db.String(256), nullable=False)
    perfil = db.Column(db.String(20), nullable=False, default='professor')
    ativo = db.Column(db.Boolean, default=True)
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)

    relatorios = db.relationship('Relatorio', backref='autor', lazy=True)

    def set_senha(self, senha):
        # bcrypt com salt aleatório por senha
        self.senha_hash = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_senha(self, senha):
        h = self.senha_hash or ''
        if h.startswith('$2'):   # hash bcrypt
            try:
                return bcrypt.checkpw(senha.encode('utf-8'), h.encode('utf-8'))
            except ValueError:
                return False
        # Hash da versão antiga (Werkzeug/scrypt): confere e converte para bcrypt
        if werkzeug_check_hash(h, senha):
            self.set_senha(senha)
            db.session.commit()
            return True
        return False

    @property
    def is_admin(self):
        return self.perfil == 'admin'

    @property
    def is_gestor(self):
        return self.perfil in ['admin', 'gestor']

    @property
    def perfil_label(self):
        labels = {'admin': 'Administrador', 'gestor': 'Coordenador', 'professor': 'Professor'}
        return labels.get(self.perfil, self.perfil.capitalize())


class SolicitacaoSenha(db.Model):
    """Pedido de redefinição de senha feito na tela de login (RF02 / C002).
    O administrador atende definindo uma nova senha no Painel Administrativo."""
    __tablename__ = 'solicitacao_senha'
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id', ondelete='CASCADE'), nullable=False)
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)
    atendida = db.Column(db.Boolean, default=False, nullable=False)
    atendida_em = db.Column(db.DateTime)

    usuario = db.relationship('Usuario', backref=db.backref(
        'solicitacoes_senha', cascade='all, delete-orphan', lazy=True))


class Aluno(db.Model):
    __tablename__ = 'aluno'
    id = db.Column(db.Integer, primary_key=True)
    matricula = db.Column(db.String(20), unique=True, nullable=False)
    nome_completo = db.Column(db.String(150), nullable=False)
    data_nascimento = db.Column(db.Date, nullable=False)
    serie = db.Column(db.String(20), nullable=False)
    pontos_fortes = db.Column(db.Text, nullable=False)
    desafios = db.Column(db.Text, nullable=False)
    nome_responsavel = db.Column(db.String(100), nullable=False)
    telefone_responsavel = db.Column(db.String(25), nullable=False)
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)

    diagnostico = db.relationship(
        'Diagnostico', backref='aluno', uselist=False, cascade='all, delete-orphan'
    )
    relatorios = db.relationship(
        'Relatorio', backref='aluno', lazy=True, cascade='all, delete-orphan'
    )

    @property
    def idade(self):
        hoje = date.today()
        b = self.data_nascimento
        return hoje.year - b.year - ((hoje.month, hoje.day) < (b.month, b.day))

    @property
    def neurodivergencias(self):
        return self.diagnostico.neurodivergencias if self.diagnostico else []


class Diagnostico(db.Model):
    __tablename__ = 'diagnostico'
    id = db.Column(db.Integer, primary_key=True)
    aluno_id = db.Column(db.Integer, db.ForeignKey('aluno.id', ondelete='CASCADE'),
                         unique=True, nullable=False)
    descricao = db.Column(db.Text, nullable=False)
    necessidades = db.Column(db.Text, nullable=False)
    acomodacoes = db.Column(db.Text, nullable=False)
    laudo = db.Column(db.String(255))          # caminho do arquivo (upload – RF09)
    atualizado_em = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    neurodivergencias = db.relationship(
        'Neurodivergencia', secondary=possui, lazy='joined',
        order_by='Neurodivergencia.nome', backref=db.backref('diagnosticos', lazy=True)
    )


class Neurodivergencia(db.Model):
    __tablename__ = 'neurodivergencia'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), unique=True, nullable=False)
    sigla = db.Column(db.String(20))
    descricao = db.Column(db.Text, nullable=False)


class Relatorio(db.Model):
    """Entidade Item de Histórico do DER."""
    __tablename__ = 'relatorio'
    id = db.Column(db.Integer, primary_key=True)
    aluno_id = db.Column(db.Integer, db.ForeignKey('aluno.id'), nullable=False)
    autor_id = db.Column(db.Integer, db.ForeignKey('usuario.id', ondelete='SET NULL'))
    tipo = db.Column(db.String(30), nullable=False)
    data_ocorrencia = db.Column(db.Date, nullable=False)
    titulo = db.Column(db.String(200), nullable=False)
    descricao = db.Column(db.Text, nullable=False)
    registrado_por = db.Column(db.String(100), nullable=False)  # nome do autor no momento do registro
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)
    atualizado_em = db.Column(db.DateTime)


# ─────────────────────────────────────────────
# LOGIN MANAGER
# ─────────────────────────────────────────────

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Usuario, int(user_id))


# ─────────────────────────────────────────────
# DECORATORS
# ─────────────────────────────────────────────

def gestor_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_gestor:
            flash('Acesso restrito a coordenadores.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Acesso restrito ao administrador.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def escola_required(f):
    """Telas de alunos/relatórios/neurodivergências: o administrador não acessa dados de alunos."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if current_user.is_admin:
            return redirect(url_for('admin'))
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────
# CONSTANTS & HELPERS
# ─────────────────────────────────────────────

SERIES = [
    '1º Ano', '2º Ano', '3º Ano', '4º Ano', '5º Ano',
    '6º Ano', '7º Ano', '8º Ano', '9º Ano',
    '1º EM', '2º EM', '3º EM'
]

# Carga inicial da tabela de neurodivergências (pode ser alterada pelos gestores – C012)
NEURODIVERGENCIAS_INICIAIS = [
    ('Transtorno do Déficit de Atenção com Hiperatividade', 'TDAH',
     'Transtorno do neurodesenvolvimento caracterizado por padrões persistentes de desatenção '
     'e/ou hiperatividade-impulsividade que interferem no funcionamento e no desenvolvimento.'),
    ('Transtorno do Espectro Autista', 'TEA',
     'Transtorno do neurodesenvolvimento caracterizado por diferenças na comunicação e interação '
     'social e por padrões restritos e repetitivos de comportamento, interesses ou atividades.'),
    ('Dislexia', None,
     'Transtorno específico da aprendizagem que afeta a precisão e/ou fluência no reconhecimento '
     'de palavras, a decodificação e a ortografia.'),
    ('Discalculia', None,
     'Transtorno específico da aprendizagem que afeta o senso numérico, a memorização de fatos '
     'aritméticos e a precisão ou fluência de cálculo.'),
    ('Transtorno Opositor Desafiador', 'TOD',
     'Padrão frequente e persistente de humor raivoso/irritável, comportamento questionador/'
     'desafiante ou índole vingativa.'),
    ('Altas Habilidades/Superdotação', 'AH/SD',
     'Potencial elevado em uma ou mais áreas (intelectual, acadêmica, criativa, artística, de '
     'liderança ou psicomotora), com grande envolvimento com a aprendizagem.'),
]

TIPOS_RELATORIO = ['Progresso', 'Conquista', 'Comportamento', 'Ocorrência']

BADGES_NEURO = ['badge-tdah', 'badge-autismo', 'badge-dislexia', 'badge-altas', 'badge-outro']

TIPO_BADGE = {
    'Progresso': 'badge-progresso',
    'Conquista': 'badge-conquista',
    'Comportamento': 'badge-comportamento',
    'Ocorrência': 'badge-ocorrencia',
}


def neuro_badge(n):
    """Cor do selo de uma neurodivergência (fixa por id)."""
    return BADGES_NEURO[(n.id - 1) % len(BADGES_NEURO)] if n and n.id else 'badge-outro'


def neuro_rotulo(n):
    return n.sigla or n.nome


def campos_obrigatorios(form, campos):
    """Retorna a lista de campos vazios (validação no servidor)."""
    return [c for c in campos if not form.get(c, '').strip()]


def excede_limite(form, limites):
    """Retorna o primeiro campo que passa do tamanho máximo da coluna, ou None."""
    for campo, (rotulo, maximo) in limites.items():
        if len(form.get(campo, '').strip()) > maximo:
            return f'O campo "{rotulo}" aceita no máximo {maximo} caracteres.'
    return None


EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
SENHA_MIN = 6


def erro_senha(senha):
    if len(senha) < SENHA_MIN:
        return f'A senha deve ter pelo menos {SENHA_MIN} caracteres.'
    if len(senha.encode('utf-8')) > 72:   # limite do bcrypt
        return 'A senha deve ter no máximo 72 caracteres.'
    return None


def destino_seguro(url):
    """Aceita apenas caminhos internos (evita redirecionar para outro site após o login)."""
    if not url:
        return None
    p = urlparse(url)
    if p.scheme or p.netloc or not url.startswith('/') or url.startswith('//') or '\\' in url:
        return None
    return url


def ler_data(valor):
    try:
        return datetime.strptime(valor, '%Y-%m-%d').date()
    except (ValueError, TypeError):
        return None


def pode_alterar_relatorio(rel):
    """Cada usuário edita e exclui os seus próprios relatórios, sem limite de tempo.
    Relatórios sem autor (usuário que foi excluído do sistema) podem ser alterados por coordenadores."""
    if not current_user.is_authenticated or current_user.is_admin:
        return False
    if rel.autor_id is None:
        return current_user.is_gestor
    return rel.autor_id == current_user.id


def enviar_email(destino, assunto, corpo):
    """Envia e-mail em segundo plano, usando as credenciais do arquivo .env (MAIL_*).
    Sem configuração, o texto é apenas mostrado no terminal. Retorna True se o envio foi tentado."""
    servidor = os.environ.get('MAIL_SERVER')
    usuario = os.environ.get('MAIL_USERNAME')
    senha = os.environ.get('MAIL_PASSWORD')
    if not (servidor and usuario and senha):
        print('[E-MAIL NÃO CONFIGURADO] Mensagem que seria enviada a', destino)
        print('Assunto:', assunto)
        print(corpo)
        return False

    msg = EmailMessage()
    msg['Subject'] = assunto
    msg['From'] = os.environ.get('MAIL_REMETENTE') or usuario
    msg['To'] = destino
    msg.set_content(corpo)
    porta = int(os.environ.get('MAIL_PORT', '587'))
    usar_tls = os.environ.get('MAIL_USE_TLS', '1') == '1'

    def _enviar():
        try:
            if usar_tls:
                with smtplib.SMTP(servidor, porta, timeout=20) as smtp:
                    smtp.starttls()
                    smtp.login(usuario, senha)
                    smtp.send_message(msg)
            else:
                with smtplib.SMTP_SSL(servidor, porta, timeout=20) as smtp:
                    smtp.login(usuario, senha)
                    smtp.send_message(msg)
        except Exception as e:   # o pedido continua registrado no Painel Administrativo
            print('[ERRO AO ENVIAR E-MAIL]', type(e).__name__, e)

    threading.Thread(target=_enviar, daemon=True).start()
    return True


MESES = ['janeiro', 'fevereiro', 'março', 'abril', 'maio', 'junho', 'julho',
         'agosto', 'setembro', 'outubro', 'novembro', 'dezembro']


@app.template_filter('data_extenso')
def data_extenso(d):
    """05 de novembro de 2026 (sempre em português, independente do idioma do computador)."""
    return f'{d.day:02d} de {MESES[d.month - 1]} de {d.year}' if d else ''


@app.context_processor
def inject_globals():
    return dict(
        pode_alterar=pode_alterar_relatorio,
        series=SERIES,
        tipos_relatorio=TIPOS_RELATORIO,
        neuro_badge=neuro_badge,
        neuro_rotulo=neuro_rotulo,
        tipo_badge=TIPO_BADGE,
    )


# ─────────────────────────────────────────────
# SEGURANÇA – sessão, cabeçalhos e CSRF
# ─────────────────────────────────────────────

@app.before_request
def controlar_inatividade():
    """RNF02: encerra a sessão após MINUTOS_INATIVIDADE minutos sem atividade."""
    if request.endpoint == 'static':
        return
    if current_user.is_authenticated:
        agora = time.time()
        ultimo = session.get('ultimo_acesso')
        if ultimo and agora - ultimo > MINUTOS_INATIVIDADE * 60:
            logout_user()
            session.clear()
            if request.endpoint == 'sessao_ping':
                return jsonify(ok=False), 401
            flash(f'Sua sessão foi encerrada após {MINUTOS_INATIVIDADE} minutos de inatividade. '
                  'Faça login novamente.', 'warning')
            return redirect(url_for('login', next=request.full_path if request.method == 'GET' else None))
        session.permanent = True
        session['ultimo_acesso'] = agora


@app.after_request
def cabecalhos_seguranca(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'same-origin'
    if current_user.is_authenticated:
        # páginas com dados de alunos não ficam guardadas no cache do navegador
        resp.headers['Cache-Control'] = 'no-store'
    return resp


@app.errorhandler(CSRFError)
def csrf_invalido(e):
    flash('O formulário expirou ou é inválido. Tente novamente.', 'warning')
    return redirect(url_for('index') if current_user.is_authenticated else url_for('login'))


@app.route('/sessao/ping', methods=['POST'])
@login_required
def sessao_ping():
    """Chamado pela página quando o usuário está ativo (digitando, clicando) sem trocar de tela."""
    return jsonify(ok=True)


@app.context_processor
def inject_sessao():
    return dict(minutos_inatividade=MINUTOS_INATIVIDADE)


# ─────────────────────────────────────────────
# ROUTES – AUTH
# ─────────────────────────────────────────────

@app.route('/')
@login_required
def index():
    if current_user.is_admin:
        return redirect(url_for('admin'))
    return redirect(url_for('dashboard'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        senha = request.form.get('senha', '')
        user = Usuario.query.filter_by(email=email, ativo=True).first()
        if user and user.check_senha(senha):
            session.clear()
            login_user(user)
            session.permanent = True
            session['ultimo_acesso'] = time.time()
            return redirect(destino_seguro(request.args.get('next')) or url_for('index'))
        flash('Email ou senha incorretos.', 'danger')
    return render_template('login.html')


@app.route('/logout')
def logout():
    logout_user()
    session.clear()
    if request.args.get('inatividade'):
        flash(f'Sua sessão foi encerrada após {MINUTOS_INATIVIDADE} minutos de inatividade. '
              'Faça login novamente.', 'warning')
    return redirect(url_for('login'))


@app.route('/esqueci-senha', methods=['GET', 'POST'])
def esqueci_senha():
    """C002 – Recuperar senha: o pedido é enviado ao administrador, que define a nova senha."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        if not email or len(email) > 120:
            flash('Informe o seu email institucional.', 'danger')
            return render_template('esqueci_senha.html', email=email)
        user = Usuario.query.filter_by(email=email, ativo=True).first()
        if not user:
            flash('Este email não foi encontrado no sistema. Confira o endereço digitado.', 'danger')
            return render_template('esqueci_senha.html', email=email)
        if user.is_admin:
            flash('A senha do administrador é redefinida pelo terminal: '
                  'flask --app app redefinir-senha ' + user.email, 'warning')
            return render_template('esqueci_senha.html', email=email)

        pendente = SolicitacaoSenha.query.filter_by(usuario_id=user.id, atendida=False).first()
        if pendente:
            flash('Você já tem uma solicitação em andamento. Aguarde o administrador '
                  'definir a sua nova senha e enviá-la ao seu email.', 'info')
            return redirect(url_for('login'))

        db.session.add(SolicitacaoSenha(usuario=user))
        db.session.commit()

        admin_user = Usuario.query.filter_by(perfil='admin', ativo=True).first()
        if admin_user:
            enviar_email(
                admin_user.email,
                'SEI Digital – Solicitação de redefinição de senha',
                f'O usuário abaixo solicitou a redefinição de senha no SEI Digital.\n\n'
                f'Nome:  {user.nome}\n'
                f'Email: {user.email}\n'
                f'Cargo: {user.cargo or "—"}\n'
                f'Data:  {datetime.now().strftime("%d/%m/%Y %H:%M")}\n\n'
                f'Para atender, entre no Painel Administrativo do SEI Digital'
                f'{" (" + os.environ["APP_URL"].rstrip("/") + "/admin)" if os.environ.get("APP_URL") else ""}, '
                f'clique no ícone de lápis do usuário, defina a nova senha e envie-a ao email dele.\n'
            )
        flash('Solicitação enviada ao administrador. Ele definirá uma nova senha e a enviará '
              'ao seu email institucional.', 'success')
        return redirect(url_for('login'))
    return render_template('esqueci_senha.html', email='')


# ─────────────────────────────────────────────
# ROUTES – DASHBOARD
# ─────────────────────────────────────────────

@app.route('/dashboard')
@login_required
@escola_required
def dashboard():
    total_alunos = Aluno.query.count()
    total_relatorios = Relatorio.query.count()
    series_distintas = db.session.query(func.count(func.distinct(Aluno.serie))).scalar() or 0
    media = round(total_relatorios / total_alunos, 1) if total_alunos > 0 else 0

    neuro_dist = (db.session.query(Neurodivergencia, func.count(Diagnostico.id))
                  .join(possui, possui.c.neurodivergencia_id == Neurodivergencia.id)
                  .join(Diagnostico, Diagnostico.id == possui.c.diagnostico_id)
                  .group_by(Neurodivergencia.id)
                  .order_by(func.count(Diagnostico.id).desc())
                  .all())
    neuro_dist = [(neuro_rotulo(n), c) for n, c in neuro_dist]
    serie_dist = (db.session.query(Aluno.serie, func.count(Aluno.id))
                  .group_by(Aluno.serie).all())
    serie_dist.sort(key=lambda x: SERIES.index(x[0]) if x[0] in SERIES else 99)
    relatorios_recentes = (Relatorio.query
                           .order_by(Relatorio.data_ocorrencia.desc())
                           .limit(5).all())

    return render_template('dashboard.html',
                           total_alunos=total_alunos,
                           total_relatorios=total_relatorios,
                           series_distintas=series_distintas,
                           media=media,
                           neuro_dist=neuro_dist,
                           serie_dist=serie_dist,
                           relatorios_recentes=relatorios_recentes)


# ─────────────────────────────────────────────
# ROUTES – ALUNOS  (C003 Visualizar aluno / C007 Manter aluno)
# ─────────────────────────────────────────────

CAMPOS_ALUNO = ['matricula', 'nome_completo', 'data_nascimento', 'serie', 'pontos_fortes',
                'desafios', 'nome_responsavel', 'telefone_responsavel']


def _salvar_aluno(aluno):
    """Valida o formulário e preenche o aluno. Retorna mensagem de erro ou None."""
    f = request.form
    if campos_obrigatorios(f, CAMPOS_ALUNO):
        return 'Preencha todos os campos obrigatórios (*).'
    erro = excede_limite(f, {'matricula': ('Matrícula', 20), 'nome_completo': ('Nome Completo', 150),
                             'nome_responsavel': ('Nome do Responsável', 100),
                             'telefone_responsavel': ('Telefone de Contato', 25)})
    if erro:
        return erro
    data_nasc = ler_data(f['data_nascimento'])
    if not data_nasc or data_nasc > date.today() or data_nasc.year < 1900:
        return 'Data de nascimento inválida.'
    if f['serie'] not in SERIES:
        return 'Selecione uma série válida.'
    matricula = f['matricula'].strip()
    outro = Aluno.query.filter_by(matricula=matricula).first()
    if outro and outro.id != aluno.id:
        return f'A matrícula {matricula} já pertence a outro aluno.'

    aluno.matricula = matricula
    aluno.nome_completo = f['nome_completo'].strip()
    aluno.data_nascimento = data_nasc
    aluno.serie = f['serie']
    aluno.pontos_fortes = f['pontos_fortes'].strip()
    aluno.desafios = f['desafios'].strip()
    aluno.nome_responsavel = f['nome_responsavel'].strip()
    aluno.telefone_responsavel = f['telefone_responsavel'].strip()
    return None


@app.route('/alunos')
@login_required
@escola_required
def alunos_lista():
    busca = request.args.get('busca', '').strip()
    serie_filtro = request.args.get('serie', '')

    query = Aluno.query
    if busca:
        query = query.filter(db.or_(Aluno.nome_completo.ilike(f'%{busca}%'),
                                    Aluno.matricula.ilike(f'%{busca}%')))
    if serie_filtro:
        query = query.filter(Aluno.serie == serie_filtro)
    alunos = query.order_by(Aluno.nome_completo).all()

    return render_template('alunos/lista.html', alunos=alunos,
                           busca=busca, serie_filtro=serie_filtro)


@app.route('/alunos/novo', methods=['GET', 'POST'])
@login_required
@gestor_required
@escola_required
def alunos_novo():
    if request.method == 'POST':
        aluno = Aluno()
        erro = _salvar_aluno(aluno)
        if erro:
            flash(erro, 'danger')
            return render_template('alunos/form.html', aluno=None, dados=request.form)
        db.session.add(aluno)
        db.session.commit()
        flash(f'Aluno {aluno.nome_completo} cadastrado. Agora registre o diagnóstico do aluno.', 'success')
        return redirect(url_for('diagnostico_form', aluno_id=aluno.id))

    return render_template('alunos/form.html', aluno=None, dados={})


@app.route('/alunos/<int:id>')
@login_required
@escola_required
def alunos_detalhe(id):
    aluno = db.get_or_404(Aluno, id)
    return render_template('alunos/detalhe.html', aluno=aluno)


@app.route('/alunos/<int:id>/editar', methods=['GET', 'POST'])
@login_required
@gestor_required
@escola_required
def alunos_editar(id):
    aluno = db.get_or_404(Aluno, id)
    if request.method == 'POST':
        erro = _salvar_aluno(aluno)
        if erro:
            db.session.rollback()
            flash(erro, 'danger')
            return render_template('alunos/form.html', aluno=aluno, dados=request.form)
        db.session.commit()
        flash('Dados do aluno atualizados com sucesso!', 'success')
        return redirect(url_for('alunos_detalhe', id=aluno.id))

    return render_template('alunos/form.html', aluno=aluno, dados={})


@app.route('/alunos/<int:id>/excluir', methods=['POST'])
@login_required
@gestor_required
@escola_required
def alunos_excluir(id):
    aluno = db.get_or_404(Aluno, id)
    nome = aluno.nome_completo
    db.session.delete(aluno)
    db.session.commit()
    flash(f'Aluno {nome} excluído com sucesso.', 'success')
    return redirect(url_for('alunos_lista'))


# ─────────────────────────────────────────────
# ROUTES – DIAGNÓSTICO  (C006 Consultar / C008 Manter diagnóstico)
# ─────────────────────────────────────────────

@app.route('/alunos/<int:aluno_id>/diagnostico', methods=['GET', 'POST'])
@login_required
@gestor_required
@escola_required
def diagnostico_form(aluno_id):
    """Cria o diagnóstico (se o aluno ainda não tiver) ou edita o existente."""
    aluno = db.get_or_404(Aluno, aluno_id)
    diag = aluno.diagnostico
    neuros = Neurodivergencia.query.order_by(Neurodivergencia.nome).all()

    if request.method == 'POST':
        f = request.form
        ids = [int(i) for i in f.getlist('neurodivergencias') if i.isdigit()]
        selecionadas = Neurodivergencia.query.filter(Neurodivergencia.id.in_(ids)).all() if ids else []
        erro = None
        if campos_obrigatorios(f, ['descricao', 'necessidades', 'acomodacoes']):
            erro = 'Preencha todos os campos obrigatórios (*).'
        elif not selecionadas:
            erro = 'Selecione ao menos uma neurodivergência.'
        if erro:
            flash(erro, 'danger')
            return render_template('diagnosticos/form.html', aluno=aluno, diag=diag,
                                   neuros=neuros, dados=f, marcadas=ids)

        novo = diag is None
        if novo:
            diag = Diagnostico(aluno=aluno)
            db.session.add(diag)
        diag.descricao = f['descricao'].strip()
        diag.necessidades = f['necessidades'].strip()
        diag.acomodacoes = f['acomodacoes'].strip()
        diag.neurodivergencias = selecionadas
        db.session.commit()
        flash('Diagnóstico cadastrado com sucesso!' if novo else 'Diagnóstico atualizado com sucesso!',
              'success')
        return redirect(url_for('alunos_detalhe', id=aluno.id))

    marcadas = [n.id for n in diag.neurodivergencias] if diag else []
    return render_template('diagnosticos/form.html', aluno=aluno, diag=diag,
                           neuros=neuros, dados={}, marcadas=marcadas)


@app.route('/alunos/<int:aluno_id>/diagnostico/excluir', methods=['POST'])
@login_required
@gestor_required
@escola_required
def diagnostico_excluir(aluno_id):
    aluno = db.get_or_404(Aluno, aluno_id)
    if aluno.diagnostico:
        db.session.delete(aluno.diagnostico)
        db.session.commit()
        flash('Diagnóstico excluído com sucesso.', 'success')
    return redirect(url_for('alunos_detalhe', id=aluno.id))


# ─────────────────────────────────────────────
# ROUTES – NEURODIVERGÊNCIAS  (C011 Consultar / C012 Manter neurodivergência)
# ─────────────────────────────────────────────

@app.route('/neurodivergencias')
@login_required
@escola_required
def neuro_lista():
    neuros = Neurodivergencia.query.order_by(Neurodivergencia.nome).all()
    return render_template('neurodivergencias/lista.html', neuros=neuros)


@app.route('/neurodivergencias/<int:id>')
@login_required
@escola_required
def neuro_detalhe(id):
    neuro = db.get_or_404(Neurodivergencia, id)
    alunos = sorted((d.aluno for d in neuro.diagnosticos), key=lambda a: a.nome_completo)
    return render_template('neurodivergencias/detalhe.html', neuro=neuro, alunos=alunos)


def _salvar_neuro(neuro):
    f = request.form
    if campos_obrigatorios(f, ['nome', 'descricao']):
        return 'Preencha todos os campos obrigatórios (*).'
    erro = excede_limite(f, {'nome': ('Nome', 100), 'sigla': ('Sigla', 20)})
    if erro:
        return erro
    nome = f['nome'].strip()
    outra = Neurodivergencia.query.filter(func.lower(Neurodivergencia.nome) == nome.lower()).first()
    if outra and outra.id != neuro.id:
        return f'Já existe uma neurodivergência chamada "{nome}".'
    neuro.nome = nome
    neuro.sigla = f.get('sigla', '').strip() or None
    neuro.descricao = f['descricao'].strip()
    return None


@app.route('/neurodivergencias/nova', methods=['GET', 'POST'])
@login_required
@gestor_required
@escola_required
def neuro_nova():
    if request.method == 'POST':
        neuro = Neurodivergencia()
        erro = _salvar_neuro(neuro)
        if erro:
            flash(erro, 'danger')
            return render_template('neurodivergencias/form.html', neuro=None, dados=request.form)
        db.session.add(neuro)
        db.session.commit()
        flash(f'Neurodivergência "{neuro.nome}" cadastrada com sucesso!', 'success')
        voltar = request.args.get('voltar_aluno', type=int)
        if voltar:
            return redirect(url_for('diagnostico_form', aluno_id=voltar))
        return redirect(url_for('neuro_lista'))
    return render_template('neurodivergencias/form.html', neuro=None, dados={})


@app.route('/neurodivergencias/<int:id>/editar', methods=['GET', 'POST'])
@login_required
@gestor_required
@escola_required
def neuro_editar(id):
    neuro = db.get_or_404(Neurodivergencia, id)
    if request.method == 'POST':
        erro = _salvar_neuro(neuro)
        if erro:
            db.session.rollback()
            flash(erro, 'danger')
            return render_template('neurodivergencias/form.html', neuro=neuro, dados=request.form)
        db.session.commit()
        flash('Neurodivergência atualizada com sucesso!', 'success')
        return redirect(url_for('neuro_detalhe', id=neuro.id))
    return render_template('neurodivergencias/form.html', neuro=neuro, dados={})


@app.route('/neurodivergencias/<int:id>/excluir', methods=['POST'])
@login_required
@gestor_required
@escola_required
def neuro_excluir(id):
    neuro = db.get_or_404(Neurodivergencia, id)
    em_uso = len(neuro.diagnosticos)
    if em_uso:
        flash(f'Não é possível excluir "{neuro.nome}": ela está em {em_uso} diagnóstico(s). '
              'Remova-a dos diagnósticos antes de excluir.', 'danger')
        return redirect(url_for('neuro_detalhe', id=neuro.id))
    nome = neuro.nome
    db.session.delete(neuro)
    db.session.commit()
    flash(f'Neurodivergência "{nome}" excluída com sucesso.', 'success')
    return redirect(url_for('neuro_lista'))


# ─────────────────────────────────────────────
# ROUTES – RELATÓRIOS  (C004 Manter histórico / C005 Consultar histórico)
# ─────────────────────────────────────────────

@app.route('/relatorios')
@login_required
@escola_required
def relatorios_lista():
    busca = request.args.get('busca', '').strip()
    tipo_filtro = request.args.get('tipo', '')

    query = Relatorio.query.join(Aluno)
    if busca:
        query = query.filter(
            db.or_(
                Relatorio.titulo.ilike(f'%{busca}%'),
                Aluno.nome_completo.ilike(f'%{busca}%'),
            )
        )
    if tipo_filtro:
        query = query.filter(Relatorio.tipo == tipo_filtro)

    relatorios = query.order_by(Relatorio.data_ocorrencia.desc()).all()
    return render_template('relatorios/lista.html', relatorios=relatorios,
                           busca=busca, tipo_filtro=tipo_filtro)


@app.route('/relatorios/novo', methods=['GET', 'POST'])
@login_required
@escola_required
def relatorios_novo():
    alunos = Aluno.query.order_by(Aluno.nome_completo).all()
    aluno_id_presel = request.args.get('aluno_id', '')
    hoje = date.today().strftime('%Y-%m-%d')

    if request.method == 'POST':
        f = request.form
        aluno = db.session.get(Aluno, int(f['aluno_id'])) if f.get('aluno_id', '').isdigit() else None
        data_oc = ler_data(f.get('data_ocorrencia'))
        erro = None
        if not aluno:
            erro = 'Selecione um aluno.'
        elif campos_obrigatorios(f, ['tipo', 'titulo', 'descricao']) or f['tipo'] not in TIPOS_RELATORIO:
            erro = 'Preencha todos os campos obrigatórios (*).'
        elif not data_oc or data_oc > date.today():
            erro = 'Data inválida (a data da ocorrência não pode ser futura).'
        else:
            erro = excede_limite(f, {'titulo': ('Título', 200)})
        if erro:
            flash(erro, 'danger')
            return render_template('relatorios/form.html', alunos=alunos, hoje=hoje,
                                   aluno_id_presel=f.get('aluno_id', ''), dados=f)

        rel = Relatorio(
            aluno=aluno,
            autor_id=current_user.id,
            registrado_por=current_user.nome,
            tipo=f['tipo'],
            data_ocorrencia=data_oc,
            titulo=f['titulo'].strip(),
            descricao=f['descricao'].strip(),
        )
        db.session.add(rel)
        db.session.commit()
        flash('Relatório registrado com sucesso!', 'success')
        return redirect(url_for('relatorios_lista'))

    return render_template('relatorios/form.html', alunos=alunos, hoje=hoje,
                           aluno_id_presel=aluno_id_presel, dados={})


@app.route('/relatorios/<int:id>/editar', methods=['GET', 'POST'])
@login_required
@escola_required
def relatorios_editar(id):
    rel = db.get_or_404(Relatorio, id)
    if not pode_alterar_relatorio(rel):
        flash('Você só pode editar os relatórios registrados por você.', 'danger')
        return redirect(url_for('relatorios_lista'))
    alunos = Aluno.query.order_by(Aluno.nome_completo).all()

    if request.method == 'POST':
        f = request.form
        aluno = db.session.get(Aluno, int(f['aluno_id'])) if f.get('aluno_id', '').isdigit() else None
        data_oc = ler_data(f.get('data_ocorrencia'))
        erro = None
        if not aluno:
            erro = 'Selecione um aluno.'
        elif campos_obrigatorios(f, ['tipo', 'titulo', 'descricao']) or f['tipo'] not in TIPOS_RELATORIO:
            erro = 'Preencha todos os campos obrigatórios (*).'
        elif not data_oc or data_oc > date.today():
            erro = 'Data inválida (a data da ocorrência não pode ser futura).'
        else:
            erro = excede_limite(f, {'titulo': ('Título', 200)})
        if erro:
            flash(erro, 'danger')
            return render_template('relatorios/form.html', alunos=alunos, rel=rel,
                                   hoje=date.today().strftime('%Y-%m-%d'),
                                   aluno_id_presel=f.get('aluno_id', ''), dados=f)

        rel.aluno = aluno
        rel.tipo = f['tipo']
        rel.data_ocorrencia = data_oc
        rel.titulo = f['titulo'].strip()
        rel.descricao = f['descricao'].strip()
        rel.atualizado_em = datetime.utcnow()
        db.session.commit()
        flash('Relatório atualizado com sucesso!', 'success')
        return redirect(url_for('relatorios_lista'))

    return render_template('relatorios/form.html', alunos=alunos, rel=rel,
                           hoje=date.today().strftime('%Y-%m-%d'),
                           aluno_id_presel=rel.aluno_id, dados={})


@app.route('/relatorios/<int:id>/excluir', methods=['POST'])
@login_required
@escola_required
def relatorios_excluir(id):
    rel = db.get_or_404(Relatorio, id)
    if not pode_alterar_relatorio(rel):
        flash('Você só pode excluir os relatórios registrados por você.', 'danger')
        return redirect(url_for('relatorios_lista'))
    db.session.delete(rel)
    db.session.commit()
    flash('Relatório excluído com sucesso.', 'success')
    return redirect(url_for('relatorios_lista'))


# ─────────────────────────────────────────────
# ROUTES – ADMIN  (C009 Manter funcionário / C010 Consultar funcionário)
# ─────────────────────────────────────────────

PERFIS = ['professor', 'gestor']


def _validar_usuario(form, email):
    if not EMAIL_RE.match(email):
        return 'Informe um email válido.'
    return excede_limite(form, {'nome': ('Nome', 100), 'email': ('Email', 120), 'cargo': ('Cargo', 50)})


@app.route('/admin')
@login_required
@admin_required
def admin():
    usuarios = (Usuario.query
                .filter(Usuario.perfil != 'admin')
                .order_by(Usuario.nome).all())
    solicitacoes = (SolicitacaoSenha.query.filter_by(atendida=False)
                    .order_by(SolicitacaoSenha.criado_em).all())
    return render_template('admin/index.html', usuarios=usuarios, solicitacoes=solicitacoes)


@app.route('/admin/solicitacoes/<int:id>/dispensar', methods=['POST'])
@login_required
@admin_required
def admin_dispensar_solicitacao(id):
    sol = db.get_or_404(SolicitacaoSenha, id)
    sol.atendida = True
    sol.atendida_em = datetime.utcnow()
    db.session.commit()
    flash('Solicitação marcada como atendida.', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/usuarios', methods=['POST'])
@login_required
@admin_required
def admin_criar_usuario():
    nome = request.form.get('nome', '').strip()
    cargo = request.form.get('cargo', '').strip() or None
    email = request.form.get('email', '').strip().lower()
    senha = request.form.get('senha', '')
    perfil = request.form.get('perfil', 'professor')

    if not all([nome, email, senha]):
        flash('Preencha todos os campos obrigatórios.', 'danger')
        return redirect(url_for('admin'))
    erro = _validar_usuario(request.form, email) or erro_senha(senha)
    if erro:
        flash(erro, 'danger')
        return redirect(url_for('admin'))
    if perfil not in PERFIS:
        perfil = 'professor'
    if Usuario.query.filter_by(email=email).first():
        flash('Este email já está cadastrado.', 'danger')
        return redirect(url_for('admin'))

    user = Usuario(nome=nome, cargo=cargo, email=email, perfil=perfil)
    user.set_senha(senha)
    db.session.add(user)
    db.session.commit()
    flash(f'Usuário {nome} criado com sucesso!', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/usuarios/<int:id>/editar', methods=['POST'])
@login_required
@admin_required
def admin_editar_usuario(id):
    user = db.get_or_404(Usuario, id)
    nome = request.form.get('nome', '').strip()
    cargo = request.form.get('cargo', '').strip() or None
    email = request.form.get('email', '').strip().lower()
    perfil = request.form.get('perfil', 'professor')
    nova_senha = request.form.get('senha', '').strip()

    if not all([nome, email]):
        flash('Nome e email são obrigatórios.', 'danger')
        return redirect(url_for('admin'))
    erro = _validar_usuario(request.form, email) or (erro_senha(nova_senha) if nova_senha else None)
    if erro:
        flash(erro, 'danger')
        return redirect(url_for('admin'))
    if perfil not in PERFIS:
        perfil = user.perfil

    existente = Usuario.query.filter_by(email=email).first()
    if existente and existente.id != id:
        flash('Este email já está em uso por outro usuário.', 'danger')
        return redirect(url_for('admin'))

    user.nome = nome
    user.cargo = cargo
    user.email = email
    user.perfil = perfil
    if nova_senha:
        user.set_senha(nova_senha)
        # a nova senha atende os pedidos de redefinição pendentes deste usuário
        for sol in SolicitacaoSenha.query.filter_by(usuario_id=user.id, atendida=False).all():
            sol.atendida = True
            sol.atendida_em = datetime.utcnow()
    db.session.commit()
    flash(f'Usuário {nome} atualizado com sucesso!', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/usuarios/<int:id>/excluir', methods=['POST'])
@login_required
@admin_required
def admin_excluir_usuario(id):
    user = db.get_or_404(Usuario, id)
    nome = user.nome
    # Os relatórios do usuário permanecem no histórico (o nome do autor fica em registrado_por)
    Relatorio.query.filter_by(autor_id=user.id).update({'autor_id': None})
    db.session.delete(user)
    db.session.commit()
    flash(f'Usuário {nome} excluído com sucesso.', 'success')
    return redirect(url_for('admin'))


# ─────────────────────────────────────────────
# INIT DB
# ─────────────────────────────────────────────

def seed_inicial():
    if not Usuario.query.filter_by(perfil='admin').first():
        email = os.environ.get('ADMIN_EMAIL', 'admin@seidigital.com').strip().lower()
        senha = os.environ.get('ADMIN_SENHA') or secrets.token_urlsafe(9)
        admin_user = Usuario(nome='Administrador', email=email, perfil='admin')
        admin_user.set_senha(senha)
        db.session.add(admin_user)
        print('=' * 60)
        print(f'Usuário administrador criado: {email}')
        if not os.environ.get('ADMIN_SENHA'):
            print(f'Senha gerada (anote, ela não será mostrada novamente): {senha}')
        print('=' * 60)
    if Neurodivergencia.query.count() == 0:
        for nome, sigla, descricao in NEURODIVERGENCIAS_INICIAIS:
            db.session.add(Neurodivergencia(nome=nome, sigla=sigla, descricao=descricao))
    db.session.commit()


# Nomes usados na versão antiga do sistema → nome na tabela de neurodivergências
_MAPA_NEURO_ANTIGO = {
    'TDAH': 'Transtorno do Déficit de Atenção com Hiperatividade',
    'Autismo': 'Transtorno do Espectro Autista',
    'TEA': 'Transtorno do Espectro Autista',
    'Síndrome de Asperger': 'Transtorno do Espectro Autista',
    'TOD': 'Transtorno Opositor Desafiador',
    'Altas Habilidades': 'Altas Habilidades/Superdotação',
}


def migrar_banco_antigo():
    """Converte um banco da versão anterior (diagnóstico/neurodivergência dentro do aluno)
    para o modelo atual, sem perder dados. Só roda uma vez, se encontrar o formato antigo."""
    insp = inspect(db.engine)
    if 'aluno' not in insp.get_table_names():
        return
    colunas_aluno = {c['name'] for c in insp.get_columns('aluno')}
    if 'diagnostico' not in colunas_aluno:
        return  # já está no formato novo

    print('Banco no formato antigo encontrado. Migrando...')
    with db.engine.begin() as con:
        con.execute(text('ALTER TABLE relatorio RENAME TO relatorio_antigo'))
        con.execute(text('ALTER TABLE aluno RENAME TO aluno_antigo'))
        if 'cargo' not in {c['name'] for c in insp.get_columns('usuario')}:
            con.execute(text('ALTER TABLE usuario ADD COLUMN cargo VARCHAR(50)'))

    db.create_all()
    seed_inicial()

    with db.engine.connect() as con:
        alunos = con.execute(text('SELECT * FROM aluno_antigo')).mappings().all()
        relatorios = con.execute(text('SELECT * FROM relatorio_antigo')).mappings().all()

    for a in alunos:
        criado = a['criado_em']
        ano = str(criado)[:4] if criado else str(date.today().year)
        aluno = Aluno(
            id=a['id'], matricula=f'{ano}{a["id"]:04d}',
            nome_completo=a['nome_completo'],
            data_nascimento=datetime.strptime(str(a['data_nascimento']), '%Y-%m-%d').date(),
            serie=a['serie'], pontos_fortes=a['pontos_fortes'], desafios=a['desafios'],
            nome_responsavel=a['nome_responsavel'], telefone_responsavel=a['telefone_responsavel'],
            criado_em=datetime.fromisoformat(str(criado)) if criado else None,
        )
        nome_neuro = _MAPA_NEURO_ANTIGO.get(a['neurodivergencia'], a['neurodivergencia'])
        neuro = Neurodivergencia.query.filter_by(nome=nome_neuro).first()
        if not neuro:
            neuro = Neurodivergencia(nome=nome_neuro, descricao='(cadastrada automaticamente na migração)')
            db.session.add(neuro)
        aluno.diagnostico = Diagnostico(
            descricao=a['diagnostico'], necessidades=a['necessidades_especificas'],
            acomodacoes=a['acomodacoes'], neurodivergencias=[neuro],
        )
        db.session.add(aluno)
    db.session.flush()

    for r in relatorios:
        autor = Usuario.query.filter(func.lower(Usuario.nome) == (r['registrado_por'] or '').lower()).first()
        db.session.add(Relatorio(
            id=r['id'], aluno_id=r['aluno_id'], autor_id=autor.id if autor else None,
            tipo=r['tipo'],
            data_ocorrencia=datetime.strptime(str(r['data_ocorrencia']), '%Y-%m-%d').date(),
            titulo=r['titulo'], descricao=r['descricao'], registrado_por=r['registrado_por'],
            criado_em=datetime.fromisoformat(str(r['criado_em'])) if r['criado_em'] else None,
        ))
    db.session.commit()

    with db.engine.begin() as con:
        con.execute(text('DROP TABLE relatorio_antigo'))
        con.execute(text('DROP TABLE aluno_antigo'))
    print(f'Migração concluída: {len(alunos)} aluno(s) e {len(relatorios)} relatório(s).')


with app.app_context():
    migrar_banco_antigo()
    db.create_all()
    seed_inicial()


@app.cli.command('redefinir-senha')
@click.argument('email')
def redefinir_senha(email):
    """Define uma nova senha para um usuário (inclusive o administrador).
    Uso:  flask --app app redefinir-senha admin@seidigital.com"""
    user = Usuario.query.filter_by(email=email.strip().lower()).first()
    if not user:
        click.echo(f'Usuário {email} não encontrado.')
        return
    senha = click.prompt('Nova senha', hide_input=True, confirmation_prompt='Repita a senha')
    erro = erro_senha(senha)
    if erro:
        click.echo(erro)
        return
    user.set_senha(senha)
    db.session.commit()
    click.echo(f'Senha de {user.nome} atualizada.')


if __name__ == '__main__':
    # Modo debug só quando FLASK_DEBUG=1 no .env (nunca em produção)
    app.run(debug=os.environ.get('FLASK_DEBUG') == '1')
