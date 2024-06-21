from collections import Counter

import pandas as pd
from sklearn.linear_model import LinearRegression
from flask import Flask, render_template, request, jsonify, Blueprint
import numpy as np
from app import db
from userapp import User

predict_app = Blueprint('predict_app', __name__)

# 连接到数据库并获取数据的函数（假设已有）

def get_data():
    # 获取联系人数据
    contacts = User.query.all()
    data = {
        'date': [contact.created_at for contact in contacts],
        'value': [len(contact.phone) for contact in contacts]  # 假设用电话号码长度为预测值
    }
    df = pd.DataFrame(data)
    return df

@predict_app.route('/trend')
def trend():
    # 获取并处理数据
    df = get_data()
    df['date'] = pd.to_datetime(df['date'])
    df = df.groupby(df['date'].dt.to_period('M')).size().reset_index(name='count')
    df['date'] = df['date'].dt.to_timestamp()

    # 线性回归
    X = np.array((df['date'] - df['date'].min()).dt.days).reshape(-1, 1)
    y = df['count'].values
    model = LinearRegression()
    model.fit(X, y)

    # 预测未来
    future_dates = pd.date_range(df['date'].max(), periods=12, freq='ME')
    future_X = np.array((future_dates - df['date'].min()).days).reshape(-1, 1)
    future_y = model.predict(future_X)

    original_data = [{'date': date, 'value': value} for date, value in zip(df['date'], df['count'])]
    future_data = [{'date': str(date), 'predicted_value': value} for date, value in zip(future_dates, future_y)]

    return render_template('prediction.html', original_data=original_data, future_data=future_data)
