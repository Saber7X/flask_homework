from flask import Flask, render_template, render_template, redirect, url_for, session, request, Blueprint
from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from sqlalchemy.sql.functions import current_user
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from flask_bcrypt import Bcrypt
from flask_login import current_user, login_user, logout_user, login_required, LoginManager, UserMixin
from app import db, bcrypt, login_manager

app = Flask(__name__)



users = Blueprint('users', __name__)

# 数据库表
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)  # 新增管理员字段

    def __repr__(self):
        return f"User('{self.email}')"

# 表单类视图
class RegistrationForm(FlaskForm):
    email = StringField('邮箱地址', validators=[DataRequired(), Email(), Length(min=6, max=120)])
    password = PasswordField('密码', validators=[DataRequired(), Length(min=6, max=60)])
    confirm_password = PasswordField('确认密码', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('注册')

class LoginForm(FlaskForm):
    email = StringField('邮箱地址', validators=[DataRequired(), Email(), Length(min=6, max=120)])
    password = PasswordField('密码', validators=[DataRequired(), Length(min=6, max=60)])
    submit = SubmitField('登录')



# 用户加载函数
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
@users.route('/')
def hello_world():  # put application's code here
    return render_template('welcome.html')

@users.route('/home')# 主页
def home():  # put application's code here
    return render_template('home.html')

@users.route('/clear')
def clear_session():
    session.clear()  # 清除会话数据
    return redirect(url_for('users.login'))


@users.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('users.home'))
    form = RegistrationForm()
    if request.method == 'POST' and form.validate_on_submit():
        # Check if email already exists
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            flash('该邮箱已被注册，请使用其他邮箱。', 'danger')
            return redirect(url_for('register'))

        # Check password requirements
        if len(form.password.data) < 8:
            flash('密码长度必须至少为8个字符。', 'danger')
            return render_template('register.html', title='注册', form=form)
        if not any(char.isdigit() for char in form.password.data):
            flash('密码必须包含至少一个数字。', 'danger')
            return render_template('register.html', title='注册', form=form)
        if not any(char.isalpha() for char in form.password.data):
            flash('密码必须包含至少一个字母。', 'danger')
            return render_template('register.html', title='注册', form=form)

        # Hash the password and create new user
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('您的账号已创建，现在可以登录！', 'success')
        session['username'] = form.email.data
        return redirect(url_for('users.login'))

    return render_template('register.html', title='Register', form=form)


@users.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        # session['username'] = current_user.username
        # print(current_user.name)
        return redirect(url_for('users.home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=True)
            session['username'] = form.email.data
            next_page = request.args.get('next')
            flash('登录成功', 'content')
            return redirect(next_page) if next_page else redirect(url_for('users.home'))
        else:
            flash('登录失败，请检查邮箱和密码', 'danger')
    return render_template('login.html', title='Login', form=form)

@users.route('/logout')
def logout():
    clear_session()
    logout_user()
    return redirect(url_for('users.home'))


