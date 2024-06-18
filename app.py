from flask import Flask, render_template, render_template, redirect, url_for, session, request
from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from sqlalchemy.sql.functions import current_user
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from flask_bcrypt import Bcrypt
from flask_login import current_user, login_user, logout_user, login_required, LoginManager, UserMixin

app = Flask(__name__)

app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Q290538T47@localhost/flask_test'
app.config['SQLALCHEMY_TRACK_MODIFICATION'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

from userapp import  users
app.register_blueprint(users)
from adminapp import admin
app.register_blueprint(admin)

from flask_migrate import Migrate # 数据库迁移配置
migrate = Migrate(app, db)
# 静态文件的 URL 路径
app.static_folder = 'static'

if __name__ == '__main__':
    app.run(debug=True)
