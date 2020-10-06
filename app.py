from flask import Flask,request,jsonify,url_for
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_mail import Mail,Message
from itsdangerous import URLSafeTimedSerializer
from flask_bcrypt import Bcrypt,generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token,jwt_required
import datetime


app = Flask (__name__)
app.config['SQLALCHEMY_DATABASE_URI']='postgresql://root:toor@localhost/flask'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]=False
app.config["SECRET_KEY"]="s1342ZXvrtdh^#$3sdfsdvxf5342136Ghlxc"
app.config["JWT_SECRET_KEY"]="t1NP63m4wnBg6nyHYKfmc2TpCOGI4nss"
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT']='587'
app.config['MAIL_USERNAME']=''
app.config['MAIL_PASSWORD']=''
app.config['DONT_REPLY_FROM_EMAIL']=''
app.config['MAIL_USE_TLS']= True


db =  SQLAlchemy(app)
ma=Marshmallow(app)
mail = Mail(app)  
ts = URLSafeTimedSerializer(app.config["SECRET_KEY"])
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

class Paciente(db.Model):
    id =db.Column (db.Integer,primary_key=True) 
    nombres=db.Column(db.String(40))
    telefono=db.Column(db.String(15),unique=True)
    email=db.Column(db.String(20),unique=True)
    password=db.Column(db.String(200))
    confirmed = db.Column(db.Boolean,  default=False)

    def __init__ (self, id,nombres,telefono,email,password):
        self.id=id
        self.nombres=nombres
        self.telefono=telefono
        self.email=email
        self.password=password

    def hash_password(self):
        self.password = generate_password_hash(self.password).decode('utf8')
    def check_password(self, password):
        return check_password_hash(self.password, password)


db.create_all()

class PacienteSchema(ma.Schema):
    class Meta:
        fields = ('id','nombres','email','telefono','confirmed')

paciente_schema=PacienteSchema()
pacientes_schema=PacienteSchema(many=True)



@app.route('/pacientes',methods=['POST'])
def create_paciente():
    id=request.json['id']
    nombres=request.json['nombres']
    telefono=request.json['telefono']
    email=request.json['email']
    password=request.json['password']
    
    new_paciente=Paciente(id,nombres,telefono,email,password)
    new_paciente.hash_password()
    try:
        db.session.add(new_paciente)
        db.session.commit()

        token = ts.dumps(email, salt='email-confirm-key')
        confirm_url = url_for(
                'confirm_email',
                token=token,
                _external=True)
        msg = Message("Hola "+nombres,
                sender="arenas782@gmail.com",
                recipients=["arenas782@gmail.com"])
       
        msg.body= confirm_url
        msg.html =confirm_url
        mail.send(msg)
    except:
        return jsonify({"mensaje":"Ha ocurrido un error1"})
    return paciente_schema.jsonify(new_paciente)


@app.route('/pacientes/<token>',methods=['GET'])
def confirm_email(token):
    try:
        email = ts.loads(token, salt="email-confirm-key", max_age=86400)
    except:
        return jsonify({"mensaje":"Ha ocurrido un error2"})
    paciente =Paciente.query.filter_by(email=email).first_or_404()
    paciente.confirmed= True
    db.session.commit()
    return paciente_schema.jsonify(paciente)

@app.route('/pacientes',methods=['GET'])
def get_pacientes():
    all_pacientes=Paciente.query.all()
    result=pacientes_schema.dump(all_pacientes)
    return jsonify(result)

@app.route('/pacientes/<id>',methods=['GET'])
def get_paciente(id):
    try:

        paciente=Paciente.query.get(id)
        return paciente_schema.jsonify(paciente)    
    except:
        return jsonify({"mensaje":"Ha ocurrido un error3"})


@app.route('/pacientes/<id>',methods=['PUT'])
def update_paciente(id):
    try:
        paciente=Paciente.query.get(id)
        nombres=request.json['nombres'] 
        paciente.nombres=nombres
        db.session.commit()
    except:
        return jsonify({"mensaje":"Ha ocurrido un error4"})
    return paciente_schema.jsonify(paciente)


@app.route('/pacientes/<id>',methods=['DELETE'])
def delete_paciente(id):
    try:
        paciente=Paciente.query.get(id)
        db.session.delete(paciente)
        db.session.commit()
        return paciente_schema.jsonify(paciente)
    except:
        return jsonify({"mensaje":"Ha ocurrido un error5"})



@app.route('/login',methods=['GET'])
def check_login():
    email=request.json['email']
    password=request.json['password']
    paciente=Paciente.query.filter_by(email=email).one_or_none()
    
    if (paciente):
        if(paciente.confirmed):
            authorized=paciente.check_password(password)
            expires = datetime.timedelta(days=7)
            access_token = create_access_token(identity=str(paciente.id), expires_delta=expires)
            return jsonify({"token":access_token})
        else:
            return jsonify({"mensaje":"Usuario no ha verificado registro"})        
    else:
        return jsonify({"mensaje":"Usuario no encontrado"})
    



@app.route('/',methods=['GET'])
@jwt_required
def index():
    return jsonify({"mensaje":"Bienvenido al API de heippi.com"})



if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000,debug=True)
    