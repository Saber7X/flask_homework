from flask import Blueprint, render_template, flash, redirect, url_for, session, request
from app import db, bcrypt
from userapp import User
from flask_login import login_required, current_user

# 创建名为 'admin' 的蓝图实例
admin = Blueprint('admin', __name__)

# 定义管理员页面的路由和视图函数
@admin.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if not session.get("username"):
        flash('尚未登陆。', 'danger')
        return redirect(url_for('users.home'))

    # 检查当前用户是否为管理员
    if not current_user.is_admin:
        flash('你没有权限访问该页面。', 'danger')
        return redirect(url_for('users.home'))

    # 查询所有用户信息
    users = User.query.all()
    return render_template('admin.html', title='Admin Dashboard', users=users)

# 定义添加用户的路由和视图函数
@admin.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        flash('你没有权限进行此操作。', 'danger')
        return redirect(url_for('users.home'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        phone = request.form.get('phone')
        is_admin = request.form.get('is_admin') == 'on'

        # 验证邮箱是否已存在
        if User.query.filter_by(email=email).first():
            flash('该邮箱已存在。', 'danger')
        else:
            if not email or not password:
                flash('邮箱和密码不能为空。', 'danger')
            else:
                new_user = User(email=email, phone = phone, password=bcrypt.generate_password_hash(password).decode('utf-8'), is_admin=is_admin)
                db.session.add(new_user)
                db.session.commit()
                flash('用户已创建。', 'success')
                return redirect(url_for('admin.admin_dashboard'))

    return render_template('add_user.html', title='Add User')

# 定义编辑用户的路由和视图函数
@admin.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        flash('你没有权限进行此操作。', 'danger')
        return redirect(url_for('users.home'))

    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')
        is_admin = request.form.get('is_admin') == 'on'

        # 验证邮箱是否已存在（排除当前编辑的用户）
        if User.query.filter(User.email == email, User.id != user.id).first():
            flash('该邮箱已存在。', 'danger')
        if User.query.filter(User.phone == phone, User.id != user.id).first():
            flash('该电话号码已存在。', 'danger')
        else:
            if not email:
                flash('邮箱不能为空。', 'danger')
            else:
                user.email = email
                user.phone = phone
                user.is_admin = is_admin
                if password:
                    user.password = bcrypt.generate_password_hash(password).decode('utf-8')
                db.session.commit()
                flash('用户信息已更新。', 'success')
                return redirect(url_for('admin.admin_dashboard'))

    return render_template('edit_user.html', title='Edit User', user=user)

# 定义删除用户的路由和视图函数
@admin.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('你没有权限进行此操作。', 'danger')
        return redirect(url_for('users.home'))

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('用户已删除。', 'success')
    return redirect(url_for('admin.admin_dashboard'))
