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
           
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                session['username']=username
                session['user_id'] = user['Sno']
                flash('Login successful','success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password')
        except mysql.connector.Error as err:
            flash(f'Database Error: {err}', 'danger')
        finally:
            cursor.close()
            conn.close()
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

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM task WHERE user_id=%s", (user_id,))
            tasks = cursor.fetchall()
            print(tasks)
        except mysql.connector.Error as err:
            flash(f'Database Error: {err}', 'danger')
            tasks = []
        finally:
            cursor.close()
            conn.close()
        return render_template('dashboard.html', tasks=tasks)
    else:
        flash("You are not logged in", 'danger')
        return redirect(url_for("login"))

@app.route('/add-task',methods=['GET','POST'])
def add_task():
    if 'user_id' in session:
        if request.method=='POST':
            title=request.form['title']
            description=request.form['description']
            due_date=request.form['duedate']
            status=request.form['status']
            priority=request.form['priority']
            assigned_to=request.form['assignedto']
            user_id = session['user_id']
            conn=get_db_connection()
            cursor=conn.cursor()
            try:
                query="insert into task (title,description,due_date,status,priority,assigned_to,user_id) values(%s,%s,%s,%s,%s,%s,%s)"
                cursor.execute(query,(title,description,due_date,status,priority,assigned_to,user_id))
                conn.commit()
                flash("task added successfully",'success')
                return redirect(url_for('dashboard'))
            except mysql.connector.Error as err:
                flash(f'Error:{err}','danger')
            finally:
                cursor.close()
                conn.close()
                return redirect(url_for('dashboard'))  
        else:
            return render_template('add_task.html')
    else:
        flash("You are not logged in", 'danger')
        return redirect(url_for("login"))




@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username',None)
    flash("You have been logged out", 'info')
    return redirect(url_for("login"))

if __name__=='__main__':
    app.run(debug=True)
