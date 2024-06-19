from functools import wraps
import secrets
import bcrypt
from flask import Flask, abort, flash, redirect, render_template, session,url_for, request
import mysql.connector
from flask import request, jsonify
from flask_wtf.csrf import CSRFProtect

app=Flask(__name__)
app.secret_key='a_very_secrete_key_123456'

# CSRF protection setup
@app.before_request
def csrf_protect():
    if request.method == 'POST':
        csrf_token = session.pop('_csrf_token', None)
        if not csrf_token or csrf_token != request.form.get('csrf_token'):
            abort(403)

# Function to generate CSRF token
def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']
app.jinja_env.globals['csrf_token'] = generate_csrf_token

# Database connection  
def get_db_connection():
    conn=mysql.connector.connect(
        user='root',
        password='1234',
        host='localhost',
        database='tasksmanagement'
    )
    return conn

# Function to check if user is logged in and is admin
def login_required_admin(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if 'type' not in session or session['type'] != 'admin':
            flash('You must be an admin to view this page', 'danger')
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['POST','GET'])
def login():
    if request.method=='POST':
        # csrf_token = session.pop('_csrf_token', None)
        # if not csrf_token or csrf_token != request.form.get('csrf_token'):
        #     abort(403)
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
                session['type']=user['type']
                flash('Login successful','success')
                if user['type'] == 'admin':  # Assuming 'type' column specifies user type
                    return redirect(url_for('task_details'))
                else:
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
        csrf_token = session.pop('_csrf_token', None)
        if not csrf_token or csrf_token != request.form.get('csrf_token'):
            abort(403)
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


@app.route('/delete-task/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    if 'user_id' in session:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("DELETE FROM task WHERE id = %s AND user_id = %s", (task_id, session['user_id']))
            conn.commit()
            return jsonify({'message': 'Task deleted successfully'})
        except mysql.connector.Error as err:
            return jsonify({'error': f'Error: {err}'}), 500
        finally:
            cursor.close()
            conn.close()
    else:
        return jsonify({'error': 'Unauthorized'}), 401



@app.route('/task-details',methods=['GET','POST'])
@login_required_admin
def task_details():
    try:      
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("select * from task")
        task=cursor.fetchall()
        print(task)
        return render_template('tasks.html',task=task)
    except Exception as e:
        print(e)
    finally:
        cursor.close()
        conn.close()
    return redirect(url_for('login')) 

    

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username',None)
    session.pop('type', None)
    flash("You have been logged out", 'info')
    return redirect(url_for("login"))

if __name__=='__main__':
    app.run(debug=True)
