from flask import Flask, render_template, request, redirect, url_for, flash, session
import psycopg
from werkzeug.security import check_password_hash, generate_password_hash
from psycopg.rows import dict_row
from bcrypt import checkpw
import os

# إعداد Flask
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['DEBUG'] = True


# إعدادات الاتصال بقاعدة البيانات
DB_NAME = "*****"
DB_USER = "*****"
DB_PASSWORD = "*****"
DB_HOST = "*****"
DB_PORT = "******"

# إنشاء اتصال بقاعدة البيانات
def get_db_connection():
    conn = psycopg.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT,
        row_factory=dict_row  # للحصول على النتائج كقواميس
    )
    return conn

# دالة لإنشاء صفحة للتأكد من الاتصال بقاعدة البيانات
@app.route('/test_connection')  
def test_connection():  
    conn = None
    try:  
        conn = get_db_connection()
        return "Database connection successful"  
    except Exception as error:  
        return f"Database connection failed: {error}", 500
    finally:
        if conn is not None:
            conn.close()    


# الصفحة الرئيسية
@app.route("/")
def index():
    return render_template("index.html")


#صفحة تسجيل الدخول للمسؤول
@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form["admin_email"]
        password = request.form["admin_password"]

        with get_db_connection() as conn:
            result = conn.execute("""
                SELECT * FROM users 
                WHERE email = %s AND password_hash = crypt(%s, password_hash)
            """, (email, password))
            user = result.fetchone()

            if user and user['role'] == 'admin':  # التحقق من أن المستخدم مسؤول
                session['admin_logged_in'] = True  # حفظ حالة تسجيل الدخول
                flash("Admin login successful!", "success")
                return redirect(url_for("admin_dashboard"))  # التوجيه إلى صفحة المسؤول
            else:
                flash("Invalid credentials or access denied.", "danger")

    return render_template("admin-login.html")

@app.route("/admin-dashboard")
def admin_dashboard():
    # التحقق من إذا كان المستخدم قد سجل الدخول كمسؤول
    if not session.get('admin_logged_in'):  # إذا لم يتم تسجيل الدخول
        flash("You must log in as an admin to access this page.", "danger")
        return redirect(url_for("admin_login"))  # إعادة التوجيه إلى صفحة تسجيل الدخول
    return render_template("admin-dashboard.html")  # عرض صفحة المسؤول إذا تم تسجيل الدخول


@app.route("/logout")
def logout():
    session.clear()  # حذف جميع بيانات الجلسة
    flash("You have been logged out.", "info")
    return redirect(url_for("admin_login"))


# اعادة تحويل الصفحات عند النقر عليها الى الصفحة نفسها من اجل ان يعمل الموقع 
@app.route("/add_user")
def add_user():
    return redirect(url_for("admin_dashboard"))

@app.route("/edit_user")
def edit_user():
    return redirect(url_for("admin_dashboard"))

@app.route("/delete_user")
def delete_user():
    return redirect(url_for("admin_dashboard"))

@app.route("/view_users")
def view_users():
    return redirect(url_for("admin_dashboard"))

@app.route("/general_settings")
def general_settings():
    return redirect(url_for("admin_dashboard"))

@app.route("/security_settings")
def security_settings():
    return redirect(url_for("admin_dashboard"))

@app.route("/notification_settings")
def notification_settings():
    return redirect(url_for("admin_dashboard"))

@app.route("/generate_reports")
def generate_reports():
    return redirect(url_for("admin_dashboard"))

@app.route("/view_reports")
def view_reports():
    return redirect(url_for("admin_dashboard"))

@app.route("/assign_permissions")
def assign_permissions():
    return redirect(url_for("admin_dashboard"))

@app.route("/edit_permissions")
def edit_permissions():
    return redirect(url_for("admin_dashboard"))

@app.route("/view_permissions")
def view_permissions():
    return redirect(url_for("admin_dashboard"))

@app.route("/manage_account")
def manage_account():
    return redirect(url_for("admin_dashboard"))

@app.route("/change_password")
def change_password():
    return redirect(url_for("admin_dashboard"))



#صفحة تسجيل الدخول للمسخدمين
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['userEmail']
        password = request.form['userPassword']

        # الاتصال بقاعدة البيانات والتحقق من المستخدم
        with get_db_connection() as conn:
            result = conn.execute("""
                SELECT email, password_hash, role FROM users 
                WHERE email = %s
            """, (email,))
            user = result.fetchone()

            if user:  # إذا تم العثور على المستخدم
                # التحقق من كلمة المرور باستخدام check_password_hash
                if check_password_hash(user['password_hash'], password):
                    # التحقق من الدور
                    if user['role'] == 'customer':
                        session['customer_logged_in'] = True
                        flash("Customer login successful!", "success")
                        return redirect(url_for("customer_dashboard"))

                    elif user['role'] == 'supplier':
                        session['supplier_logged_in'] = True
                        flash("Supplier login successful!", "success")
                        return redirect(url_for("supplier_dashboard"))

                    elif user['role'] == 'sales_staff':
                        session['sales_staff_logged_in'] = True
                        flash("Sales staff login successful!", "success")
                        return redirect(url_for("sales_dashboard"))

                    elif user['role'] == 'warehouse_staff':
                        session['warehouse_staff_logged_in'] = True
                        flash("Supplier login successful!", "success")
                        return redirect(url_for("warehouse_dashboard"))

                else:
                    flash("Invalid password. Please try again.", "danger")
            else:
                flash("Invalid email. Please try again.", "danger")

    return render_template('login.html')

          





# صفحة العميل
@app.route('/customer')
def customer_dashboard():
    # التحقق من إذا كان المستخدم قد سجل الدخول كعميل
    if not session.get('customer_logged_in'):  # إذا لم يتم تسجيل الدخول
        flash("You must log in to access this page.", "danger")
        return redirect(url_for("login"))  # إعادة التوجيه إلى صفحة تسجيل الدخول
    return render_template("customer.html")  # عرض صفحة العميل إذا تم تسجيل الدخول


# اعادة تحويل الصفحات عند النقر عليها الى الصفحة نفسها من اجل ان يعمل الموقع 
@app.route('/view_shopping_cart')
def view_shopping_cart():
    return redirect(url_for('customer_dashboard'))

@app.route('/modify_shopping_cart')
def modify_shopping_cart():
    return redirect(url_for('customer_dashboard'))

@app.route('/checkout')
def checkout():
    return redirect(url_for('customer_dashboard'))

@app.route('/browse_products')
def browse_products():
    return redirect(url_for('customer_dashboard'))

@app.route('/product_categories')
def product_categories():
    return redirect(url_for('customer_dashboard'))

@app.route('/search_products')
def search_products():
    return redirect(url_for('customer_dashboard'))

@app.route('/view_past_orders')
def view_past_orders():
    return redirect(url_for('customer_dashboard'))

@app.route('/track_order_status_customer')
def track_order_status_customer():
    return redirect(url_for('customer_dashboard'))

@app.route('/handle_order_issues_customer')
def handle_order_issues_customer():
    return redirect(url_for('customer_dashboard'))

@app.route('/contact_customer_service')
def contact_customer_service():
    return redirect(url_for('customer_dashboard'))

@app.route('/send_inquiries')
def send_inquiries():
    return redirect(url_for('customer_dashboard'))

@app.route('/process_complaints_customer')
def process_complaints_customer():
    return redirect(url_for('customer_dashboard'))

@app.route('/manage_personal_info')
def manage_personal_info():
    return redirect(url_for('customer_dashboard'))

@app.route('/change_password_customer')
def change_password_customer():
    return redirect(url_for('customer_dashboard'))

@app.route('/update_payment_methods')
def update_payment_methods():
    return redirect(url_for('customer_dashboard'))











@app.route('/forgot-password')
def forgot_password():
    return render_template('forgot-password.html')






#صفحة المورد
@app.route('/supplier')
def supplier_dashboard():
    # التحقق من إذا كان المستخدم قد سجل الدخول كمورد
    if not session.get('supplier_logged_in'):  # إذا لم يتم تسجيل الدخول
        flash("You must log in to access this page.", "danger")
        return redirect(url_for("login"))  # إعادة التوجيه إلى صفحة تسجيل الدخول
    return render_template("supplier.html")  # عرض صفحة المورد إذا تم تسجيل الدخول


# اعادة تحويل الصفحات عند النقر عليها الى الصفحة نفسها من اجل ان يعمل الموقع 
@app.route('/send_message')
def send_message():
    return redirect(url_for('supplier_dashboard'))

@app.route('/view_notifications')
def view_notifications():
    return redirect(url_for('supplier_dashboard'))

@app.route('/add_new_product')
def add_new_product():
    return redirect(url_for('supplier_dashboard'))

@app.route('/edit_product')
def edit_product():
    return redirect(url_for('supplier_dashboard'))

@app.route('/delete_product')
def delete_product():
    return redirect(url_for('supplier_dashboard'))

@app.route('/view_new_orders_supplier')
def view_new_orders_supplier():
    return redirect(url_for('supplier_dashboard'))

@app.route('/update_order_status_supplier')
def update_order_status_supplier():
    return redirect(url_for('supplier_dashboard'))

@app.route('/manage_shipping')
def manage_shipping():
    return redirect(url_for('supplier_dashboard'))

@app.route('/update_quantities')
def update_quantities():
    return redirect(url_for('supplier_dashboard'))

@app.route('/set_warehouse_alerts')
def set_warehouse_alerts():
    return redirect(url_for('supplier_dashboard'))

@app.route('/view_sales_reports_supplier')
def view_sales_reports_supplier():
    return redirect(url_for('supplier_dashboard'))

@app.route('/analyze_product_performance')
def analyze_product_performance():
    return redirect(url_for('supplier_dashboard'))

@app.route('/user_details')
def user_details():
    return redirect(url_for('supplier_dashboard'))

@app.route('/edit_account_info')
def edit_account_info():
    return redirect(url_for('supplier_dashboard'))

@app.route('/change_password_supplier')
def change_password_supplier():
    return redirect(url_for('supplier_dashboard'))






#صفحة موضف المبيعات
@app.route('/sales-staff')
def sales_dashboard():
    # التحقق من إذا كان المستخدم قد سجل الدخول كموضف مبيعات
    if not session.get('sales_staff_logged_in'):  # إذا لم يتم تسجيل الدخول
        flash("You must log in to access this page.", "danger")
        return redirect(url_for("login"))  # إعادة التوجيه إلى صفحة تسجيل الدخول
    return render_template('sales-staff.html')




@app.route('/view_new_orders_sales')
def view_new_orders_sales():
    return redirect(url_for('sales_dashboard'))

@app.route('/track_order_status_sales_staff')
def track_order_status_sales_staff():
    return redirect(url_for('sales_dashboard'))

@app.route('/handle_order_issues_sales_staff')
def handle_order_issues_sales_staff():
    return redirect(url_for('sales_dashboard'))

@app.route('/respond_to_customers')
def respond_to_customers():
    return redirect(url_for('sales_dashboard'))

@app.route('/process_complaints_sales_staff')
def process_complaints_sales_staff():
    return redirect(url_for('sales_dashboard'))

@app.route('/create_special_offers')
def create_special_offers():
    return redirect(url_for('sales_dashboard'))

@app.route('/apply_discounts')
def apply_discounts():
    return redirect(url_for('sales_dashboard'))

@app.route('/view_sales_reports_sales_staff')
def view_sales_reports_sales_staff():
    return redirect(url_for('sales_dashboard'))

@app.route('/view_customer_feedback')
def view_customer_feedback():
    return redirect(url_for('sales_dashboard'))

@app.route('/Monitor_sales_targets')
def Monitor_sales_targets():
    return redirect(url_for('sales_dashboard'))





#صفحة موظف المستودع
@app.route('/warehouse')
def warehouse_dashboard():
        # التحقق من إذا كان المستخدم قد سجل الدخول كموضف مستودع
    if not session.get('warehouse_staff_logged_in'):  # إذا لم يتم تسجيل الدخول
        flash("You must log in to access this page.", "danger")
        return redirect(url_for("login"))  # إعادة التوجيه إلى صفحة تسجيل الدخول
    return render_template('warehouse.html')



# اعادة تحويل الصفحات عند النقر عليها الى الصفحة نفسها من اجل ان يعمل الموقع 

@app.route('/view_current_warehouse')
def view_current_warehouse():
    return redirect(url_for('warehouse_dashboard'))

@app.route('/update_product_quantities')
def update_product_quantities():
    return redirect(url_for('warehouse_dashboard'))

@app.route('/add_new_products')
def add_new_products():
    return redirect(url_for('warehouse_dashboard'))

@app.route('/set_reorder_points')
def set_reorder_points():
    return redirect(url_for('warehouse_dashboard'))

@app.route('/update_order_status_warehouhe_staff')
def update_order_status_warehouhe_staff():
    return redirect(url_for('warehouse_dashboard'))

@app.route('/prepare_orders')
def prepare_orders():
    return redirect(url_for('warehouse_dashboard'))

@app.route('/receive_new_orders')
def receive_new_orders():
    return redirect(url_for('warehouse_dashboard'))

@app.route('/schedule_shipments')
def schedule_shipments():
    return redirect(url_for('warehouse_dashboard'))

@app.route('/track_shipments')
def track_shipments():
    return redirect(url_for('warehouse_dashboard'))

@app.route('/manage_returns')
def manage_returns():
    return redirect(url_for('warehouse_dashboard'))

@app.route('/warehouse_reports')
def warehouse_reports():
    return redirect(url_for('warehouse_dashboard'))

@app.route('/analyze_warehouse_turnover')
def analyze_warehouse_turnover():
    return redirect(url_for('warehouse_dashboard'))

@app.route('/Orders_and_shipment_reports')
def Orders_and_shipment_reports():
    return redirect(url_for('warehouse_dashboard'))




#تسجي الخروج للمستخدمين
@app.route("/logout_users")
def logout_users():
    session.clear()  # حذف جميع بيانات الجلسة
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))




#صفحة التسجيل الجديد للمستخدمين
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # استلام البيانات من نموذج التسجيل
        username = request.form['username']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        confirm_password = request.form['confirmPassword']
        role = request.form['role']  # الدور (admin, supplier, customer, sales_staff, warehouse_staff)

        # التحقق من صحة البيانات
        if not username or not email or not phone or not password or not confirm_password or not role:
            flash("All fields are required!", "danger")
            return redirect(url_for('register'))

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('register'))

        try:
            # الاتصال بقاعدة البيانات
            conn = get_db_connection()

            with conn.cursor() as cursor:
                # التحقق من أن البريد الإلكتروني أو اسم المستخدم غير مستخدم مسبقًا
                cursor.execute("SELECT * FROM users WHERE email = %s OR username = %s", (email, username))
                existing_user = cursor.fetchone()

                if existing_user:
                    flash("Email or username is already registered!", "danger")
                    return redirect(url_for('register'))

                # تشفير كلمة المرور
                hashed_password = generate_password_hash(password)

                # إدخال المستخدم الجديد في جدول users
                cursor.execute("""
                    INSERT INTO users (username, email, password_hash, role)
                    VALUES (%s, %s, %s, %s) RETURNING user_id
                """, (username, email, hashed_password, role))
                user_id = cursor.fetchone()["user_id"]

                # إدخال بيانات المستخدم في الجدول المناسب بناءً على الدور
                if role == "customer":
                    cursor.execute("""
                        INSERT INTO Customers (user_id, CustomerName, CustomerAddress, PhoneNumber)
                        VALUES (%s, %s, %s, %s)
                    """, (user_id, username, 'Default Address', phone))

                elif role == "supplier":
                    cursor.execute("""
                        INSERT INTO Suppliers (user_id, SupplierName, SupplierAddress, SupplierRating, Email, PhoneNumber)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (user_id, username, 'Default Address', 0.0, email, phone))

                elif role == "sales_staff":
                    print(f"Registering sales_staff with user_id: {user_id}")
                    # يتم تخزين بيانات موضف المبيعات في جدول المستخدمين فقط
                    pass


                elif role == "warehouse_staff":
                    print(f"Registering warehouse_staff with user_id: {user_id}")
                    cursor.execute("""
                        INSERT INTO Warehouse (user_id, WarehouseLocation, QuantityAvailable, ProductID)
                        VALUES (%s, %s, %s, %s)
                    """, (user_id, 'Default Location', 0, None))  # ProductID يمكن أن يكون NULL

                # حفظ التغييرات
                conn.commit()

                flash("Registration successful! You can now log in.", "success")
                return redirect(url_for('login'))

        except Exception as e:
            # التراجع عن أي تغييرات في حالة حدوث خطأ
            flash("An error occurred during registration. Please try again.", "danger")
            print(f"Error: {e}")
            return redirect(url_for('register'))

        finally:
            # إغلاق الاتصال بقاعدة البيانات
            conn.close()

    # عرض صفحة التسجيل
    return render_template('register.html')





@app.route("/about")
def about():
    return render_template("about.html")

if __name__ == "__main__":  

    app.run(debug=True)
