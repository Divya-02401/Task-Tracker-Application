import bcrypt
from flask import Flask, flash, redirect, render_template, session,url_for, request
import mysql.connector

app=Flask(__name__)
app.secret_key='a_very_secrete_key_123456'

# Database connection  
def get_db_connection():
    conn=mysql.connector.connect(
        user='root',
        password='1234',
        host='localhost',
        database='tasksmanagement'
    )
    return conn

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST','GET'])
def login():
    if request.method=='POST':
        username=request.form['username']
        password=request.form['password']
        try:
            conn=get_db_connection()
            cursor=conn.cursor(dictionary=True)
            cursor.execute("select * from user where username=%s",(username,))
            user=cursor.fetchone()
            cursor.close()
            conn.close()

            if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                session['username']=username
                flash('Login successful','success')
                return redirect(url_for('user'))
            else:
                flash('Invalid username or password')
        except mysql.connector.Error as err:
            flash(f'Database Error: {err}', 'danger')
    return render_template('login.html')

@app.route('/register',methods=['POST','GET'])
def register():
    if request.method=='POST':
        username=request.form['username']
        password=request.form['password']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        email=request.form['email']
        conn=get_db_connection()
        cursor=conn.cursor()
        try:
            query="insert into user (username,email,password) values (%s,%s,%s)"
            cursor.execute(query,(username,email,hashed_password))
            conn.commit()
            flash('Registration Successful!','success')
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            flash(f'Error:{err}','danger')
        finally:
            cursor.close()
            conn.close()
    return render_template('register.html')

@app.route('/user')
def user():
    if 'username' in session:
        return render_template("user.html")
    else:
        flash("You are not logged in",'danger')
        return redirect(url_for("login"))

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    session.pop("username",None)
    flash("You have been logged out", 'info')
    return redirect(url_for("login"))

if __name__=='__main__':
    app.run(debug=True)
