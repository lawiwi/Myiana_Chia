from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_session import Session
import os
from datetime import datetime
from dotenv import load_dotenv
from sqlalchemy import func
from werkzeug.utils import secure_filename
import cloudinary
import cloudinary.uploader
load_dotenv()

app = Flask(__name__, template_folder='Templates')

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev_secret')
DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

cloudinary.config(
    cloudinary_url=os.getenv("CLOUDINARY_URL")
)
# Session en filesystem (útil para debug y Deploy básicos)
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

db = SQLAlchemy(app)
with app.app_context():
    db.create_all()
# Modelo de usuario
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='Explorador')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relaciones con los modelos de detalle (añadimos cascade)
    explorador = db.relationship('Explorador', backref='user', uselist=False, cascade='all, delete-orphan')
    emprendedor = db.relationship('Emprendedor', backref='user', uselist=False, cascade='all, delete-orphan')

    # Métodos de seguridad
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Explorador(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    primer_nombre = db.Column(db.String(50))
    segundo_nombre = db.Column(db.String(50))
    primer_apellido = db.Column(db.String(50))
    segundo_apellido = db.Column(db.String(50))
    fecha_nacimiento = db.Column(db.Date)
    telefono = db.Column(db.String(20))
    preferencias = db.Column(db.String(200))

class Emprendedor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Datos personales
    primer_nombre = db.Column(db.String(50))
    segundo_nombre = db.Column(db.String(50))
    primer_apellido = db.Column(db.String(50))
    segundo_apellido = db.Column(db.String(50))
    fecha_nacimiento = db.Column(db.Date)
    telefono = db.Column(db.String(20))
    empresas = db.relationship('Empresa', backref='emprendedor', lazy=True)

class Empresa(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre_emprendimiento = db.Column(db.String(100), nullable=False)
    nit = db.Column(db.String(30), unique=True, nullable=False)
    clasificacion = db.Column(db.String(50))
    plan = db.Column(db.String(50), default='Sin Plan')
    zona = db.Column(db.String(100))
    ubicacion = db.Column(db.String(100))
    descripcion = db.Column(db.Text)
    url = db.Column(db.String(200))
    rango_precios = db.Column(db.String(50))          # nuevo: ejemplo "$ - $$ - $$$"
    imagen_filename = db.Column(db.String(200))       # nuevo: nombre de archivo en static/uploads/
    
    emprendedor_id = db.Column(db.Integer, db.ForeignKey('emprendedor.id'))
    visitas = db.relationship('Visita', backref='empresa', lazy=True)
    favoritos = db.relationship('Favorito', backref='empresa', lazy=True)  # relación

class Favorito(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    explorador_id = db.Column(db.Integer, db.ForeignKey('explorador.id'), nullable=False)
    empresa_id = db.Column(db.Integer, db.ForeignKey('empresa.id'), nullable=False)
    fecha_guardado = db.Column(db.DateTime, default=datetime.utcnow)

    explorador = db.relationship('Explorador', backref='favoritos')

class Visita(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    empresa_id = db.Column(db.Integer, db.ForeignKey('empresa.id'))
    explorador_id = db.Column(db.Integer, db.ForeignKey('explorador.id'), nullable=True)
    fecha = db.Column(db.DateTime, default=datetime.utcnow)
    tipo = db.Column(db.String(50), default='clic')  # clic, guardado, etc.

class LogAccion(db.Model):
    __tablename__ = 'log_accion'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    tipo_entidad = db.Column(db.String(100))  # Ej: "Usuario", "Emprendimiento"
    entidad_id = db.Column(db.Integer, nullable=True)  # ID del registro afectado
    accion = db.Column(db.String(200))  # Ej: "Creación", "Eliminación", "Modificación"
    detalles = db.Column(db.Text)  # Texto libre con información adicional
    fecha = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='acciones_log')

    def __repr__(self):
        return f"<LogAccion {self.id} - {self.accion} - {self.tipo_entidad}>"

# Rutas
@app.route('/BotonLog')
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.role == 'Administrador':
            return redirect(url_for('admin_dashboard'))
        elif user.role == 'Emprendedor':
            return redirect(url_for('emprendedor_dashboard'))
        else:
            return redirect(url_for('explorador_dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        role = request.form.get('role', 'Explorador')

        # Evitar duplicados
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Usuario o correo ya registrado', 'danger')
            return redirect(url_for('register'))

        # Crear el usuario base
        new_user = User(username=username, email=email, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # -------------------------------
        # Conversión segura de fecha
        # -------------------------------
        from datetime import datetime
        fecha_nacimiento_str = request.form.get('fecha_nacimiento', '').strip()
        fecha_nacimiento = None
        if fecha_nacimiento_str:
            try:
                fecha_nacimiento = datetime.strptime(fecha_nacimiento_str, "%Y-%m-%d").date()
            except ValueError:
                flash("Formato de fecha inválido. Usa AAAA-MM-DD.", "danger")
                return redirect(url_for('register'))

        # -------------------------------
        # Registro según el rol
        # -------------------------------
        if role == 'Explorador':
            nuevo_explorador = Explorador(
                user_id=new_user.id,
                primer_nombre=request.form.get('primer_nombre', '').strip(),
                segundo_nombre=request.form.get('segundo_nombre', '').strip(),
                primer_apellido=request.form.get('primer_apellido', '').strip(),
                segundo_apellido=request.form.get('segundo_apellido', '').strip(),
                fecha_nacimiento=fecha_nacimiento,
                telefono=request.form.get('telefono', '').strip(),
                preferencias=request.form.get('preferencias', '').strip()
            )
            db.session.add(nuevo_explorador)

        elif role == 'Emprendedor':
            nuevo_emprendedor = Emprendedor(
                user_id=new_user.id,
                primer_nombre=request.form.get('primer_nombre_emp', '').strip(),
                segundo_nombre=request.form.get('segundo_nombre_emp', '').strip(),
                primer_apellido=request.form.get('primer_apellido_emp', '').strip(),
                segundo_apellido=request.form.get('segundo_apellido_emp', '').strip(),
                fecha_nacimiento=fecha_nacimiento,
                telefono=request.form.get('telefono_emp', '').strip(),
            )
            db.session.add(nuevo_emprendedor)

        # Guardar todo
        db.session.commit()

        # -------------------------------
        # 📘 REGISTRO EN AUDITORÍA
        # -------------------------------
        log = LogAccion(
            entidad_id=new_user.id,
            accion="Creación",
            detalles=f"Se creó el usuario '{new_user.username}' con rol '{new_user.role}'."
        )
        db.session.add(log)
        db.session.commit()

        flash('Registro exitoso. Ya puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))

    # Si GET → mostrar el formulario
    return render_template('Base/register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['identifier'].strip()
        password = request.form['password']

        # Buscamos usuario por nombre o email
        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier)
        ).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash(f'Bienvenido {user.username}!', 'success')

            if user.role == 'Administrador':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'Emprendedor':
                return redirect(url_for('emprendedor_dashboard'))
            else:
                return redirect(url_for('explorador_dashboard'))

        else:
            flash('Credenciales incorrectas', 'danger')

    return render_template('Base/login.html')

@app.route('/emprendedor/dashboard')
def emprendedor_dashboard():
    user_id = session.get('user_id')
    if not user_id or session.get('role') != 'Emprendedor':
        flash('Por favor inicia sesión como emprendedor.', 'warning')
        return redirect(url_for('login'))

    # Buscar el emprendedor asociado al usuario actual
    emprendedor = Emprendedor.query.filter_by(user_id=user_id).first()

    if not emprendedor:
        flash('No se encontró información de emprendedor.', 'danger')
        return redirect(url_for('login'))

    # Verificar si ya tiene una empresa asociada
    empresa = Empresa.query.filter_by(emprendedor_id=emprendedor.id).first()

    # Si no existe, lo mandamos al formulario para registrar su empresa
    if not empresa:
        flash('Por favor completa la información de tu empresa antes de continuar.', 'info')
        return redirect(url_for('registrar_empresa'))

    acciones = db.session.query(LogAccion.accion, db.func.count(LogAccion.id))\
        .filter_by(user_id=user_id)\
        .group_by(LogAccion.accion)\
        .all()

    acciones_labels = [a[0] for a in acciones] or ["Sin registros"]
    acciones_values = [a[1] for a in acciones] or [0]
    favoritos_count = Favorito.query.filter_by(empresa_id=empresa.id).count()

    # Si ya tiene empresa, renderizamos el dashboard normal
    return render_template(
        'Emprededores/dashboard_emprededor.html', 
        emprendedor=emprendedor, empresa=empresa,
        acciones_labels=acciones_labels,
        acciones_values=acciones_values,
        favoritos_count=favoritos_count
        )

@app.route('/registrar_visita/<int:empresa_id>', methods=['POST'])
def registrar_visita(empresa_id):
    # Verificar si hay sesión activa
    if 'user_id' not in session or session.get('role') != 'Explorador':
        return jsonify({'success': False, 'message': 'Debes iniciar sesión como explorador.'}), 403

    user_id = session['user_id']
    explorador = Explorador.query.filter_by(user_id=user_id).first()

    if not explorador:
        return jsonify({'success': False, 'message': 'Explorador no encontrado.'}), 404

    # Registrar visita
    nueva_visita = Visita(
        empresa_id=empresa_id,
        fecha=datetime.utcnow(),
        tipo='clic'
    )
    db.session.add(nueva_visita)
    db.session.commit()

    return jsonify({'success': True})

@app.route('/api/visitas/<int:empresa_id>')
def visitas_por_dia(empresa_id):
    from datetime import datetime
    dias_semana = ['Lunes', 'Martes', 'Miércoles', 'Jueves', 'Viernes', 'Sábado', 'Domingo']
    visitas = [0] * 7  # Inicializa con 0 para los 7 días

    registros = Visita.query.filter_by(empresa_id=empresa_id).all()

    for v in registros:
        dia = v.fecha.weekday()  # Lunes=0, Domingo=6
        visitas[dia] += 1

    # Si no hay suficientes datos, generar aleatorios de respaldo
    if sum(visitas) < 5:
        import random
        visitas = [random.randint(5, 20) for _ in range(7)]

    return jsonify({
        'labels': dias_semana,
        'values': visitas
    })

@app.route('/api/visitas_dia/<int:empresa_id>/<string:dia>')
def visitas_por_dia_semana(empresa_id, dia):
    from datetime import datetime, timedelta
    import random

    dias_semana = ['Lunes', 'Martes', 'Miércoles', 'Jueves', 'Viernes', 'Sábado', 'Domingo']
    if dia not in dias_semana:
        return jsonify({'error': 'Día no válido'}), 400

    dia_index = dias_semana.index(dia)

    # Generar las últimas 10 semanas
    hoy = datetime.utcnow()
    semanas_labels = []
    visitas_semanales = []

    for i in range(10):
        semana_inicio = hoy - timedelta(weeks=i)
        semana_label = f"Semana {10 - i}"
        semanas_labels.append(semana_label)

        # Filtrar visitas reales por esa semana y día
        semana_visitas = (
            Visita.query.filter(
                Visita.empresa_id == empresa_id,
                db.extract('week', Visita.fecha) == semana_inicio.isocalendar()[1],
                db.extract('year', Visita.fecha) == semana_inicio.year
            ).all()
        )

        # Contar las que correspondan al día elegido
        count = sum(1 for v in semana_visitas if v.fecha.weekday() == dia_index)
        # Si no hay suficientes datos, generamos aleatorios
        if count == 0:
            count = random.randint(3, 15)

        visitas_semanales.append(count)

    return jsonify({
        'labels': semanas_labels[::-1],  # mostrar de la más antigua a la más reciente
        'values': visitas_semanales[::-1]
    })



@app.route('/registrar_empresa', methods=['GET', 'POST'])
def registrar_empresa():
    user_id = session.get('user_id')

    if not user_id:
        flash('Por favor inicia sesión para continuar.', 'warning')
        return redirect(url_for('login'))

    emprendedor = Emprendedor.query.filter_by(user_id=user_id).first()

    if not emprendedor:
        flash('No se encontró el perfil del emprendedor.', 'danger')
        return redirect(url_for('login'))

    empresa_existente = Empresa.query.filter_by(emprendedor_id=emprendedor.id).first()
    if empresa_existente:
        flash('Ya tienes una empresa registrada.', 'info')
        return redirect(url_for('emprendedor_dashboard'))

    if request.method == 'POST':
        nombre_emprendimiento = request.form.get('nombre_emprendimiento')
        clasificacion = request.form.get('clasificacion')
        nit = request.form.get('nit')
        zona = request.form.get('zona')
        ubicacion = request.form.get('ubicacion')
        descripcion = request.form.get('descripcion')
        rango_precios = request.form.get('rango_precios')
        url_empresa = request.form.get('url')
        imagen = request.files.get('imagen')

        # 🌟 SUBIR A CLOUDINARY
        imagen_url = None

        if imagen and imagen.filename:
            try:
                upload_result = cloudinary.uploader.upload(
                    imagen,
                    folder="myiana_empresas"   # opcional, pero ayuda
                )
                print("CLOUDINARY RESPONSE:", upload_result)  # Log en Render
                imagen_url = upload_result.get("secure_url")

            except Exception as e:
                print("ERROR SUBIENDO A CLOUDINARY:", e)
                flash("Hubo un error al subir la imagen.", "danger")

        # Crear empresa AUN SI NO HAY IMAGEN
        nueva_empresa = Empresa(
            nombre_emprendimiento=nombre_emprendimiento,
            nit=nit,
            clasificacion=clasificacion,
            zona=zona,
            ubicacion=ubicacion,
            descripcion=descripcion,
            rango_precios=rango_precios,
            url=url_empresa,
            imagen_filename=imagen_url,
            emprendedor_id=emprendedor.id
        )

        db.session.add(nueva_empresa)
        db.session.commit()

        log = LogAccion(
            accion="Creación de Empresa",
            entidad_id=nueva_empresa.id,
            detalles=f"El emprendedor {emprendedor.id} registró la empresa '{nombre_emprendimiento}'."
        )
        db.session.add(log)
        db.session.commit()

        flash('Tu empresa ha sido registrada correctamente.', 'success')
        return redirect(url_for('emprendedor_dashboard'))

    # GET
    return render_template('Emprededores/registrar_empresa.html', emprendedor=emprendedor)

@app.route('/editar_empresa/<int:id>', methods=['POST'])
def editar_empresa(id):
    empresa = Empresa.query.get_or_404(id)
    datos_antes = empresa.__dict__.copy()

    empresa.nombre_emprendimiento = request.form.get('nombre_emprendimiento', empresa.nombre_emprendimiento)
    empresa.nit = request.form.get('nit', empresa.nit)
    empresa.zona = request.form.get('zona', empresa.zona)
    empresa.ubicacion = request.form.get('ubicacion', empresa.ubicacion)
    empresa.plan = request.form.get('plan', empresa.plan)
    empresa.rango_precios = request.form.get('rango_precios', empresa.rango_precios)
    empresa.clasificacion = request.form.get('clasificacion', empresa.clasificacion)

    db.session.commit()

    # Auditoría
    cambios = []
    for campo in ['nombre_emprendimiento', 'nit', 'zona', 'ubicacion', 'plan', 'clasificacion','rango_precios']:
        if datos_antes.get(campo) != getattr(empresa, campo):
            cambios.append(f"{campo}: '{datos_antes.get(campo)}' → '{getattr(empresa, campo)}'")

    detalles = ", ".join(cambios) if cambios else "Sin cambios detectados"

    log = LogAccion(
        accion="Edición Emprendedor",
        entidad_id=empresa.id,
        user_id=session.get('user_id'),
        detalles=f"Actualizó su empresa '{empresa.nombre_emprendimiento}'. {detalles}"
    )
    db.session.add(log)
    db.session.commit()

    flash('Información actualizada correctamente.', 'success')
    return redirect(url_for('emprendedor_dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    session.pop('user_id', None)
    flash('Has cerrado sesión', 'info')
    return redirect(url_for('login'))


@app.route('/crear_admin')
def crear_admin():
    admin = User.query.filter_by(username='admin').first()
    if admin:
        return "El administrador ya existe"

    admin = User(
        username='admin',
        email='admin@myiana.com',
        role='Administrador'
    )
    admin.set_password('admin')
    db.session.add(admin)
    db.session.commit()
    return "Usuario administrador creado correctamente: admin / admin123"

# Catálogo por clasificación
@app.route('/catalogo/<string:clasificacion>')
def catalogo_clasificacion(clasificacion):
    # normalizar la clasificación si hace falta
    empresas = Empresa.query.filter(func.lower(Empresa.clasificacion) == clasificacion.lower()).all()
    # Si quieres paginar, aquí es donde lo harías
    return render_template('Catalogo/catalogo_list.html', empresas=empresas, clasificacion=clasificacion)

# Toggle favorito (guardar / quitar)
@app.route('/favorito/toggle', methods=['POST'])
def toggle_favorito():
    if 'user_id' not in session:
        return jsonify({'ok': False, 'msg': 'Necesitas iniciar sesión'}), 401

    explorador = Explorador.query.filter_by(user_id=session['user_id']).first()
    if not explorador:
        return jsonify({'ok': False, 'msg': 'Inicia sesión como explorador para guardar sus sitios favoritos!'}), 400

    empresa_id = request.json.get('empresa_id') or request.form.get('empresa_id')
    if not empresa_id:
        return jsonify({'ok': False, 'msg': 'Falta empresa_id'}), 400

    empresa = Empresa.query.get(empresa_id)
    if not empresa:
        return jsonify({'ok': False, 'msg': 'Empresa no encontrada'}), 404

    fav = Favorito.query.filter_by(explorador_id=explorador.id, empresa_id=empresa.id).first()
    nombre_usuario = explorador.user.username if hasattr(explorador, 'user') and explorador.user else f"Explorador {explorador.id}"
    if fav:
        # quitar favorito
        db.session.delete(fav)

        # Registrar auditoría
        log = LogAccion(
            user_id=session['user_id'],
            tipo_entidad='Favorito',
            entidad_id=fav.id,
            accion='Eliminación Favorito',
            detalles=f"El usuario {nombre_usuario} eliminó de favoritos la empresa {empresa.nombre_emprendimiento}",
        )
        db.session.add(log)
        db.session.commit()
        action = 'removed'
    else:
        # crear favorito
        fav = Favorito(explorador_id=explorador.id, empresa_id=empresa.id)
        db.session.add(fav)
        #Registrar auditoría
        log = LogAccion(
            user_id=session['user_id'],
            tipo_entidad='Favorito',
            entidad_id=fav.id,
            accion='Agregacion Favorito',
            detalles=f"El usuario {nombre_usuario} agregó a favoritos la empresa {empresa.nombre_emprendimiento}",
        )
        db.session.add(log)
        db.session.commit()
        action = 'added'
    db.session.commit()

    # devolver nuevo conteo de favoritos
    fav_count = Favorito.query.filter_by(empresa_id=empresa.id).count()
    return jsonify({'ok': True, 'action': action, 'favoritos_count': fav_count})


@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.route("/")
def chiaentre():
    username = session.get('username')
    role = session.get('role')
    return render_template('Base/Home.html', username=username, role=role)

with app.app_context():
    db.create_all()
        
if __name__ == '__main__':
    app.run(debug=True)


# -------------------------------------------------------------------------------------------------------------------------------------------------------------------
from collections import Counter

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'Administrador':
        flash("Tu sesión ha expirado. Inicia sesión nuevamente.", "warning")
        return redirect(url_for('login'))
    
    # Totales generales
    total_usuarios = User.query.count()
    total_exploradores = User.query.filter(func.lower(User.role) == 'explorador').count()
    total_emprendedores = User.query.filter(func.lower(User.role) == 'emprendedor').count()
    username = session.get('username')
    role = session.get('role')

    # Datos para la gráfica de roles
    roles_data = {
        'Exploradores': total_exploradores,
        'Emprendedores': total_emprendedores
    }
    
    # --- Datos para exploradores ---
    exploradores = Explorador.query.all()

    # --- Datos para emprendedores ---
    empresa = Empresa.query.all()
    emprendedores = Emprendedor.query.all()
    planes_posibles = ['Sin Plan','Valvanera', 'Castillo Marroquin', 'Diosa chia']

    logs = LogAccion.query.order_by(LogAccion.fecha.desc()).all()

    # Contar cuántos emprendedores hay por plan
    planes = [e.plan if e.plan in planes_posibles else 'Sin plan' for e in empresa]
    plan_counts = Counter(planes)

    labels_plan = planes_posibles
    values_plan = [plan_counts.get(p, 0) for p in labels_plan]

    # --- Gráfica de preferencias (Exploradores) ---
    preferencias_posibles = ['Comida', 'Deportes', 'Ocio', 'Arte y Cultura', 'Naturaleza', 'Compras']
    preferencias = [exp.preferencias for exp in exploradores if exp.preferencias in preferencias_posibles]
    preferencias_count = Counter(preferencias)

    labels_pref = preferencias_posibles
    values_pref = [preferencias_count.get(p, 0) for p in labels_pref]

    acciones_labels = ['Creación', 'Edición', 'Eliminación']

    conteo_acciones = {
        'Creación': db.session.query(func.count(LogAccion.id)).filter(LogAccion.accion.like('%Creación%')).scalar(),
        'Edición': db.session.query(func.count(LogAccion.id)).filter(LogAccion.accion.like('%Edición%')).scalar(),
        'Eliminación': db.session.query(func.count(LogAccion.id)).filter(LogAccion.accion.like('%Eliminación%')).scalar()
    }

    acciones_values = [conteo_acciones[label] for label in acciones_labels]

    return render_template(
        'Base/dashboard_admin.html',
        total_usuarios=total_usuarios,
        total_exploradores=total_exploradores,
        total_emprendedores=total_emprendedores,
        roles_data=roles_data,
        emprendedores=emprendedores,
        empresa=empresa,
        exploradores=exploradores,
        labels_plan=labels_plan,
        values_plan=values_plan,
        labels_pref=labels_pref,
        values_pref=values_pref,
        logs=logs,
        acciones_labels=acciones_labels,
        acciones_values=acciones_values,
        role=role,
        username=username
    )

# --- Ver detalles de un emprendimiento ---
@app.route('/emprendimiento/<int:id>')
def ver_emprendimiento(id):
    e = Emprendedor.query.get_or_404(id)
    return render_template('Emprededores/ver_emprendimiento.html', e=e)

# --- Ver detalles de un explorador ---
@app.route('/explorador/<int:id>')
def ver_explorador(id):
    explorador = Explorador.query.get_or_404(id)
    return render_template('Explorador/ver_explorador.html', explorador=explorador)


# --- Eliminar emprendimiento ---
@app.route('/eliminar_emprendimiento/<int:id>', methods=['POST'])
def eliminar_emprendimiento(id):
    emprendimiento = Emprendedor.query.get_or_404(id)
    user = emprendimiento.user  # Obtiene el usuario asociado

    for empresa in emprendimiento.empresas:
        db.session.delete(empresa)

    # Registrar en auditoría antes de eliminar
    log = LogAccion(
        accion='Eliminación',
        entidad_id=user.id,
        detalles=f'Se eliminó el emprendedor"{user.username}".'
    )
    db.session.add(log)

    db.session.delete(user)
    db.session.commit()

    flash('Emprendimiento eliminado completamente.', 'success')
    return redirect(url_for('admin_dashboard'))


# --- Editar emprendimiento ---
@app.route('/editar_emprendimiento/<int:id>', methods=['POST'])
def editar_emprendimiento(id):
    e = Empresa.query.get_or_404(id)

    # Guardar datos anteriores para comparar
    datos_antes = {
        "nombre_emprendimiento": e.nombre_emprendimiento,
        "nit": e.nit,
        "zona": e.zona,
        "ubicacion": e.ubicacion,
        "plan": e.plan,
        "clasificacion": e.clasificacion
    }

    # Actualizar datos
    e.nombre_emprendimiento = request.form.get('nombre_emprendimiento', e.nombre_emprendimiento)
    e.nit = request.form.get('nit', e.nit)
    e.zona = request.form.get('zona', e.zona)
    e.ubicacion = request.form.get('ubicacion', e.ubicacion)
    e.plan = request.form.get('plan', e.plan)
    e.clasificacion = request.form.get('clasificacion', e.clasificacion)

    # Guardar cambios
    db.session.commit()

    # Comparar y generar detalle de los cambios
    cambios = []
    for campo, valor_anterior in datos_antes.items():
        nuevo_valor = getattr(e, campo)
        if valor_anterior != nuevo_valor:
            cambios.append(f"{campo}: '{valor_anterior}' → '{nuevo_valor}'")

    detalles = ", ".join(cambios) if cambios else "Sin cambios detectados"

    # Registrar auditoría
    log = LogAccion(
        accion="Edición de Emprendedor",
        entidad_id=e.id,
        detalles=f"Se editaron los datos del emprendimiento '{e.nombre_emprendimiento}'. Cambios: {detalles}"
    )
    db.session.add(log)
    db.session.commit()

    flash('Información actualizada correctamente.', 'success')
    return redirect(url_for('admin_dashboard'))


# --- Eliminar explorador ---
@app.route('/eliminar_explorador/<int:id>', methods=['POST'])
def eliminar_explorador(id):
    explorador = Explorador.query.get_or_404(id)
    user = explorador.user  # Obtiene el usuario asociado

    # Registrar en auditoría antes de eliminar
    log = LogAccion(
        accion='Eliminación',
        entidad_id=user.id,
        detalles=f'Se eliminó el usuario "{user.username}" asociado al explorador "{explorador.primer_nombre,explorador.primer_apellido}".'
    )
    db.session.add(log)

    db.session.delete(user)  # Esto elimina al usuario y en cascada su registro de explorador
    db.session.commit()

    flash('Explorador eliminado completamente.', 'success')
    return redirect(url_for('admin_dashboard'))



# EDITAR EXPLORADOR
@app.route('/editar_explorador/<int:id>', methods=['POST'])
def editar_explorador(id):
    explorador = Explorador.query.get_or_404(id)

    # Guardar datos previos
    datos_antes = {
        "primer_nombre": explorador.primer_nombre,
        "segundo_nombre": explorador.segundo_nombre,
        "primer_apellido": explorador.primer_apellido,
        "segundo_apellido": explorador.segundo_apellido,
        "telefono": explorador.telefono,
        "fecha_nacimiento": explorador.fecha_nacimiento
    }

    # Actualizar campos
    explorador.primer_nombre = request.form.get('primer_nombre', explorador.primer_nombre)
    explorador.segundo_nombre = request.form.get('segundo_nombre', explorador.segundo_nombre)
    explorador.primer_apellido = request.form.get('primer_apellido', explorador.primer_apellido)
    explorador.segundo_apellido = request.form.get('segundo_apellido', explorador.segundo_apellido)
    explorador.telefono = request.form.get('telefono', explorador.telefono)

    fecha_str = request.form.get('fecha_nacimiento')
    if fecha_str:
        try:
            if isinstance(fecha_str, str):
                explorador.fecha_nacimiento = datetime.strptime(fecha_str, '%Y-%m-%d').date()
            else:
                explorador.fecha_nacimiento = fecha_str
        except Exception as e:
            flash(f'Error en la fecha ({e}). Usa el formato AAAA-MM-DD.', 'danger')
            return redirect(url_for('admin_dashboard'))

    try:
        db.session.commit()

        # Comparar cambios
        cambios = []
        for campo, valor_anterior in datos_antes.items():
            nuevo_valor = getattr(explorador, campo)
            if valor_anterior != nuevo_valor:
                cambios.append(f"{campo}: '{valor_anterior}' → '{nuevo_valor}'")

        detalles = ", ".join(cambios) if cambios else "Sin cambios detectados"

        # 🔹 Registrar auditoría
        log = LogAccion(
            accion="Edición de Explorador",
            entidad_id=explorador.id,
            detalles=f"Se editaron los datos del explorador '{explorador.primer_nombre} {explorador.primer_apellido}'. Cambios: {detalles}"
        )
        db.session.add(log)
        db.session.commit()

        flash('Explorador actualizado correctamente.', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Error al actualizar: {e}', 'danger')

    return redirect(url_for('admin_dashboard'))


@app.route('/explorador_dashboard')
def explorador_dashboard():
    if 'user_id' not in session or session.get('role') != 'Explorador':
        flash('Debes iniciar sesión como explorador.', 'warning')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])    
    explorador = Explorador.query.filter_by(user_id=user.id).first()
    #Obtener los favoritos reales del explorador
    favoritos = Favorito.query.filter_by(explorador_id=explorador.id)\
        .order_by(Favorito.fecha_guardado.desc()).all()
    
    return render_template('Explorador/dashboard_explorador.html', user=user, favoritos=favoritos, explorador=explorador)

# Ruta para recomendar un lugar por categoría
@app.route('/recomendar/<categoria>')
def recomendar_lugar(categoria):
    from random import choice
    lugares = Empresa.query.filter(Empresa.clasificacion.ilike(f'%{categoria}%')).all()
    if not lugares:
        return jsonify({'error': 'No hay lugares en esta categoría'}), 404

    lugar = choice(lugares)
    return jsonify({
        'nombre': lugar.nombre_emprendimiento,
        'descripcion': lugar.descripcion,
        'imagen': lugar.imagen_filename,,
        'url': lugar.url or '#'
    })



@app.route('/eliminar_favorito/<int:fav_id>', methods=['POST'])
def eliminar_favorito(fav_id):
    if 'user_id' not in session or session.get('role') != 'Explorador':
        flash('Debes iniciar sesión como explorador.', 'warning')
        return redirect(url_for('login'))

    favorito = Favorito.query.get_or_404(fav_id)
    explorador = Explorador.query.filter_by(user_id=session['user_id']).first()

    # Seguridad: solo puede borrar sus propios favoritos
    if favorito.explorador_id != explorador.id:
        flash('No puedes eliminar este favorito.', 'danger')
        return redirect(url_for('explorador_dashboard'))

    db.session.delete(favorito)
    db.session.commit()

    empresa = Empresa.query.get(favorito.empresa_id)
    nombre_usuario = explorador.user.username if hasattr(explorador, 'user') and explorador.user else f"Explorador {explorador.id}"

    log = LogAccion(
        user_id=session['user_id'],
        tipo_entidad='Favorito',
        entidad_id=favorito.id,
        accion='Eliminación Favorito',
        detalles=f"El usuario {nombre_usuario} eliminó de favoritos la empresa {empresa.nombre_emprendimiento}",
    )
    db.session.add(log)
    db.session.commit()
    flash('Lugar eliminado de tus favoritos.', 'success')
    return redirect(url_for('explorador_dashboard'))

@app.route('/api/auditoria_favoritos/<int:empresa_id>')
def auditoria_favoritos(empresa_id):
    """Devuelve los registros de auditoría (LogAccion) relacionados con favoritos de esta empresa."""
    logs = LogAccion.query.filter(
        LogAccion.tipo_entidad == 'Favorito',
        LogAccion.detalles.like(f'%empresa {Empresa.query.get(empresa_id).nombre_emprendimiento}%')
    ).order_by(LogAccion.fecha.desc()).limit(50).all()

    data = []
    for log in logs:
        data.append({
            'usuario': log.user.username if log.user else 'Desconocido',
            'accion': log.accion,
            'fecha': log.fecha.strftime("%Y-%m-%d %H:%M"),
            'detalles': log.detalles
        })
    return jsonify(data)

@app.route('/<string:categoria>')
def comida(categoria):
    # Busca case-insensitive
    username = session.get('username')
    role = session.get('role')
    empresas = Empresa.query.filter(func.lower(Empresa.clasificacion) == categoria.lower()).all()

    return render_template('Explorador/categoria.html',
                           categoria=categoria,
                           empresas=empresas,
                           username=username,
                           role=role)


