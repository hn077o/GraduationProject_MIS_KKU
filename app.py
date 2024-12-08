from flask import Flask, render_template, request, redirect, url_for, flash, session
import psycopg
from werkzeug.security import check_password_hash, generate_password_hash
from psycopg.rows import dict_row
from bcrypt import checkpw
import os
from datetime import date

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

            if user and user['role'] == 'admin':  # التحقق من أن المستخدم هو مسؤول النظام
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


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['userEmail']
        password = request.form['userPassword']

        # الاتصال بقاعدة البيانات والتحقق من المستخدم
        with get_db_connection() as conn:
            result = conn.execute("""
                SELECT user_id, email, password_hash, role FROM users 
                WHERE email = %s
            """, (email,))
            user = result.fetchone()

            if user:  # إذا تم العثور على المستخدم
                if check_password_hash(user['password_hash'], password):
                    # إدارة الأدوار والجلسات ديناميكيًا
                    role = user['role']
                    user_id = user['user_id']

                    session['logged_in'] = True
                    session['role'] = role
                    session['user_id'] = user_id

                    # استرداد معرّف الدور الخاص إذا لم يكن مديرًا
                    if role == 'customer':
                        session['customer_id'] = get_related_id(conn, 'Customers', 'customerid', user_id)
                        flash("Customer login successful!", "success")
                        return redirect(url_for("customer_dashboard"))

                    elif role == 'supplier':
                        session['supplier_id'] = get_related_id(conn, 'suppliers', 'supplierid', user_id)
                        flash("Supplier login successful!", "success")
                        return redirect(url_for("supplier_dashboard"))

                    elif role == 'sales_staff':
                        flash("Sales staff login successful!", "success")
                        return redirect(url_for("sales_dashboard"))

                    elif role == 'warehouse_staff':
                        flash("Warehouse staff login successful!", "success")
                        return redirect(url_for("warehouse_dashboard"))

                else:
                    flash("Invalid password. Please try again.", "danger")
            else:
                flash("Invalid email. Please try again.", "danger")

    return render_template('login.html')


# دالة للحصول على معرّف الدور المرتبط
def get_related_id(conn, table_name, column_name, user_id):
    """
    تسترد معرّف الدور المرتبط بـ user_id في جدول معين.
    """
    result = conn.execute(f"""
        SELECT {column_name} FROM {table_name}
        WHERE user_id = %s
    """, (user_id,))
    related_record = result.fetchone()
    return related_record[column_name] if related_record else None





@app.route('/customer')
def customer_dashboard():
    # التحقق من إذا كان المستخدم قد سجل الدخول كعميل
    if not session.get('logged_in') or session.get('role') != 'customer':
        flash("You must log in as a customer to access this page.", "danger")
        return redirect(url_for("login"))  # إعادة التوجيه إلى صفحة تسجيل الدخول

    customer_id = session.get('customer_id')  # جلب CustomerID من الجلسة
    if not customer_id:
        flash("Customer information is missing. Please contact support.", "danger")
        return redirect(url_for("login"))

    # عرض صفحة العميل إذا تم تسجيل الدخول
    return render_template("customer.html", customer_id=customer_id)







@app.route('/browse_products')
def browse_products():
    conn = get_db_connection()
    cur = conn.cursor(row_factory=dict_row)
    cur.execute('SELECT productid, ProductName, ProductDescription, UnitPrice FROM Products')
    products = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('browse_products.html', products=products)




@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    quantity = int(request.form.get('quantity', 1))

    # الحصول على سلة التسوق من الجلسة أو إنشاء سلة جديدة
    cart = session.get('cart', {})

    if str(product_id) in cart:
        cart[str(product_id)] += quantity
    else:
        cart[str(product_id)] = quantity

    # تحديث سلة التسوق في الجلسة
    session['cart'] = cart

    return redirect(url_for('view_shopping_cart'))







@app.route('/view_shopping_cart')
def view_shopping_cart():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cart = session.get('cart', {})
    cart_items = []
    total_amount = 0

    if cart:
        conn = get_db_connection()
        cur = conn.cursor(row_factory=dict_row)
        product_ids = [int(pid) for pid in cart.keys()]
        placeholders = ','.join(['%s'] * len(product_ids))

        cur.execute(f'''
            SELECT productid, productname, unitprice
            FROM products
            WHERE productid IN ({placeholders})
        ''', product_ids)

        products = cur.fetchall()
        cur.close()
        conn.close()

        for product in products:
            pid = str(product['productid'])
            quantity = cart[pid]
            total_price = product['unitprice'] * quantity
            total_amount += total_price
            cart_items.append({
                'productid': product['productid'],
                'productname': product['productname'],
                'unitprice': product['unitprice'],
                'quantity': quantity,
                'total_price': total_price
            })

    return render_template('view_shopping_cart.html', cart_items=cart_items, total_amount=total_amount)


@app.route('/update_cart/<int:product_id>', methods=['POST'])
def update_cart(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    quantity = int(request.form.get('quantity', 1))
    cart = session.get('cart', {})

    if str(product_id) in cart:
        if quantity > 0:
            cart[str(product_id)] = quantity
        else:
            del cart[str(product_id)]
    
    session['cart'] = cart

    return redirect(url_for('view_shopping_cart'))


@app.route('/remove_from_cart/<int:product_id>', methods=['POST'])
def remove_from_cart(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cart = session.get('cart', {})

    if str(product_id) in cart:
        del cart[str(product_id)]

    session['cart'] = cart

    return redirect(url_for('view_shopping_cart'))






@app.route('/Checkout')
def Checkout():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    # الحصول على customerid من جدول Customers
    conn = get_db_connection()
    cur = conn.cursor(row_factory=dict_row)
    cur.execute('SELECT customerid FROM customers WHERE user_id = %s', (user_id,))
    customer = cur.fetchone()

    if not customer:
        # إذا لم يتم العثور على العميل، قم بإعادة توجيه المستخدم أو عرض رسالة
        return "عذرًا، لم يتم العثور على معلومات العميل. الرجاء التأكد من تسجيل الدخول بشكل صحيح."

    customer_id = customer['customerid']

    cart = session.get('cart', {})
    if not cart:
        return redirect(url_for('view_shopping_cart'))

    # الحصول على تفاصيل المنتجات في السلة
    product_ids = [int(pid) for pid in cart.keys()]
    placeholders = ','.join(['%s'] * len(product_ids))

    cur.execute(f'''
        SELECT productid, productname, unitprice
        FROM products
        WHERE productid IN ({placeholders})
    ''', product_ids)

    products = cur.fetchall()

    total_amount = 0
    order_products = []

    for product in products:
        pid = product['productid']
        product_name = product['productname']
        unit_price = product['unitprice']
        quantity = cart[str(pid)]
        total_price = unit_price * quantity
        total_amount += total_price
        order_products.append((product_name, quantity, pid))

    # بدء معاملة
    with conn.transaction():
        # إنشاء الطلب
        cur.execute(
            'INSERT INTO orders (customerid, orderdate, orderstatus) VALUES (%s, %s, %s) RETURNING orderid',
            (customer_id, date.today(), 'Pending')
        )
        order_id = cur.fetchone()['orderid']

        # إضافة المنتجات إلى OrderProducts
        for op in order_products:
            cur.execute(
                'INSERT INTO orderproducts (nameproducts, quantity, orderid, productid) VALUES (%s, %s, %s, %s)',
                (op[0], op[1], order_id, op[2])
            )

    conn.commit()
    cur.close()
    conn.close()

    # تفريغ سلة التسوق
    session['cart'] = {}

    return render_template('order_confirmation.html', order_id=order_id)







@app.route('/track_order_status_customer')
def track_order_status_customer():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    conn = get_db_connection()
    cur = conn.cursor(row_factory=dict_row)

    # الحصول على customerid من جدول Customers
    cur.execute('SELECT customerid FROM customers WHERE user_id = %s', (user_id,))
    customer = cur.fetchone()

    if not customer:
        cur.close()
        conn.close()
        return "عذرًا، لم يتم العثور على معلومات العميل."

    customer_id = customer['customerid']

    # الحصول على أحدث طلب للعميل
    cur.execute('''
        SELECT o.orderid, o.orderstatus, o.orderdate, s.shippingdate
        FROM orders o
        LEFT JOIN shipping s ON o.orderid = s.orderid
        WHERE o.customerid = %s
        ORDER BY o.orderdate DESC
        LIMIT 1
    ''', (customer_id,))
    latest_order = cur.fetchone()

    if latest_order:
        order_id = latest_order['orderid']
        order_status = latest_order['orderstatus']
        # حساب تاريخ التسليم المتوقع (مثال: بعد 5 أيام من تاريخ الشحن)
        if latest_order['shippingdate']:
            expected_delivery_date = latest_order['shippingdate'] + timedelta(days=5)
            expected_delivery = expected_delivery_date.strftime('%Y-%m-%d')
        else:
            expected_delivery = 'Not Available'
    else:
        order_id = 'No Orders'
        order_status = 'No Current Orders'
        expected_delivery = 'Not Available'

    # جلب الطلبات السابقة
    cur.execute('''
        SELECT o.orderid, o.orderdate, o.orderstatus
        FROM orders o
        WHERE o.customerid = %s
        ORDER BY o.orderdate DESC
    ''', (customer_id,))
    orders = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('track_order_status_customer.html', order_id=order_id, order_status=order_status, expected_delivery=expected_delivery, orders=orders)






@app.route('/modify_shopping_cart')
def modify_shopping_cart():
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

@app.route('/view_orders/<int:customer_id>')
def view_orders():
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







@app.route('/supplier')
def supplier_dashboard():
    # التحقق من إذا كان المستخدم قد سجل الدخول كمورد
    if not session.get('logged_in') or session.get('role') != 'supplier':
        flash("You must log in as a supplier to access this page.", "danger")
        return redirect(url_for("login"))  # إعادة التوجيه إلى صفحة تسجيل الدخول

    supplier_id = session.get('supplier_id')  # جلب SupplierID من الجلسة
    if not supplier_id:
        flash("Supplier information is missing. Please contact support.", "danger")
        return redirect(url_for("login"))

    # عرض صفحة المورد إذا تم تسجيل الدخول
    return render_template("supplier.html", supplier_id=supplier_id)



# Define routes for each page with redirect
@app.route('/send_message')
def send_message():
    return redirect(url_for('supplier_dashboard'))

@app.route('/view_notifications')
def view_notifications():
    return redirect(url_for('supplier_dashboard'))


@app.route('/add_new_product_supplier')
def add_new_product_supplier():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('add_new_product_supplier.html')



@app.route('/add_new_product_action', methods=['POST'])
def add_new_product_action():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    supplier_id = session['supplier_id']
    warehouse_id = request.form['warehouse_id']
    warehouse_location = request.form['warehouse_location']
    product_name = request.form['product_name']
    product_description = request.form['product_description']
    unit_price = request.form['unit_price']
    quantity = request.form['quantity']

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # إدخال المنتج الجديد في قاعدة البيانات
        print("Attempting to insert new product into Products table.")
        cur.execute('''
            INSERT INTO Products (ProductName, ProductDescription, UnitPrice, SupplierID)
            VALUES (%s, %s, %s, %s) RETURNING ProductID
        ''', (product_name, product_description, unit_price, supplier_id))
        
        # التأكد من أن الإدخال تم بنجاح
        result = cur.fetchone()
        print("Insert result:", result)
        if result:
            product_id = result['productid']
            print("Product ID:", product_id)

            # إدخال البيانات في جدول Warehouse
            print("Attempting to insert data into Warehouse table.")
            cur.execute('''
                INSERT INTO Warehouse (WarehouseID, WarehouseLocation, ProductID, QuantityAvailable)
                VALUES (%s, %s, %s, %s)
            ''', (warehouse_id, warehouse_location, product_id, quantity))

            conn.commit()
            flash('Product and warehouse entry added successfully!', 'success')
        else:
            conn.rollback()
            print("Insert failed, rolling back.")
            flash('Failed to add product. Please try again.', 'danger')
    except Exception as e:
        conn.rollback()
        print("Exception occurred:", e)
        flash(f'An error occurred: {e}', 'danger')
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('add_new_product_supplier'))



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


@app.route('/view_supply_reports')
def view_supply_reports():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    supplier_id = session['supplier_id']

    conn = get_db_connection()
    cur = conn.cursor(row_factory=dict_row)

    # جلب تقارير الإمدادات المتعلقة بالمورد
    cur.execute('''
        SELECT 
            s.SupplierID AS supplier_id,
            s.SupplierName AS supplier_name,
            s.Email AS email,
            p.ProductID AS product_id,
            p.ProductName AS product_name,
            p.UnitPrice AS unit_price,
            w.WarehouseID AS warehouse_id,
            w.WarehouseLocation AS warehouse_location,
            w.QuantityAvailable AS quantity_available
        FROM Products p
        JOIN Suppliers s ON p.SupplierID = s.SupplierID
        JOIN Warehouse w ON p.ProductID = w.ProductID
        WHERE s.SupplierID = %s
        ORDER BY p.ProductID ASC
    ''', (supplier_id,))
    supply_reports = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('view_supply_reports.html', supply_reports=supply_reports)



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










@app.route('/sales-staff')
def sales_dashboard():
    # التحقق من إذا كان المستخدم قد سجل الدخول كموظف مبيعات
    if not session.get('logged_in') or session.get('role') != 'sales_staff':
        flash("You must log in as a sales staff member to access this page.", "danger")
        return redirect(url_for("login"))  # إعادة التوجيه إلى صفحة تسجيل الدخول

    # عرض صفحة موظف المبيعات إذا تم تسجيل الدخول
    return render_template("sales-staff.html")




@app.route('/view_sales_reports_sales_staff')
def view_sales_reports_sales_staff():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor(row_factory=dict_row)

    # جلب تقارير المبيعات بشكل ديناميكي
    cur.execute('''
        SELECT 
            o.OrderDate::DATE AS ReportDate,
            COUNT(DISTINCT o.OrderID) AS TotalOrders,
            SUM(op.Quantity * p.UnitPrice) AS TotalRevenue
        FROM Orders o
        JOIN OrderProducts op ON o.OrderID = op.OrderID
        JOIN Products p ON op.ProductID = p.ProductID
        GROUP BY ReportDate
        ORDER BY ReportDate DESC
    ''')
    sales_reports = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('view_sales_reports_sales_staff.html', sales_reports=sales_reports)





@app.route('/view_new_orders_sales')
def view_new_orders_sales():
    return render_template('sales-staff.html')





@app.route('/track_order_status_sales_staff', methods=['GET', 'POST'])
def track_order_status_sales_staff():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    order_id = request.args.get('order_id')
    status = request.args.get('status')

    conn = get_db_connection()
    cur = conn.cursor(row_factory=dict_row)

    query = 'SELECT orderid, customerid, orderdate, orderstatus FROM orders WHERE 1=1'
    params = []

    if order_id:
        query += ' AND orderid = %s'
        params.append(order_id)
    if status:
        query += ' AND orderstatus = %s'
        params.append(status)

    query += ' ORDER BY orderdate DESC'

    cur.execute(query, params)
    orders = cur.fetchall()
    cur.close()
    conn.close()

    return render_template('track_order_status_sales_staff.html', orders=orders)



@app.route('/order_details_sales_staff/<int:order_id>')
def order_details_sales_staff(order_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor(row_factory=dict_row)

    # جلب معلومات الطلب
    cur.execute('''
        SELECT o.OrderID, o.OrderDate, o.OrderStatus, c.CustomerName
        FROM Orders o
        JOIN Customers c ON o.CustomerID = c.CustomerID
        WHERE o.OrderID = %s
    ''', (order_id,))
    order = cur.fetchone()

    if not order:
        return "Order not found."

    # جلب تفاصيل المنتجات في الطلب
    cur.execute('''
        SELECT p.ProductName, op.Quantity, p.UnitPrice
        FROM OrderProducts op
        JOIN Products p ON op.ProductID = p.ProductID
        WHERE op.OrderID = %s
    ''', (order_id,))
    order_items = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('order_details_sales_staff.html', order=order, order_items=order_items)





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



@app.route('/view_customer_feedback')
def view_customer_feedback():
    return redirect(url_for('sales_dashboard'))

@app.route('/Monitor_sales_targets')
def Monitor_sales_targets():
    return redirect(url_for('sales_dashboard'))








@app.route('/warehouse')
def warehouse_dashboard():
    # التحقق من إذا كان المستخدم قد سجل الدخول كموظف مستودع
    if not session.get('logged_in') or session.get('role') != 'warehouse_staff':
        flash("You must log in as a warehouse staff member to access this page.", "danger")
        return redirect(url_for("login"))  # إعادة التوجيه إلى صفحة تسجيل الدخول

    user_id = session.get('user_id')  # جلب WarehouseID من الجلسة
    if not user_id:
        flash("Warehouse staff information is missing. Please contact support.", "danger")
        return redirect(url_for("login"))

    # عرض صفحة موظف المستودع إذا تم تسجيل الدخول
    return render_template("warehouse.html", user_id=user_id)





@app.route('/add_new_products', methods=['GET', 'POST'])
def add_new_products():
   return redirect(url_for('warehouse_dashboard'))




@app.route('/warehouse_reports')
def warehouse_reports():
    if not session.get('logged_in') or session.get('role') != 'warehouse_staff':
        flash("You must log in as a warehouse staff member to view this page.", "danger")
        return redirect(url_for("login"))

    user_id = session.get('user_id')

    if not user_id:
        flash("Warehouse information is missing. Please contact support.", "danger")
        return redirect(url_for("login"))

    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT 
                    products.productname AS product_name, 
                    warehouse.quantityavailable AS available_quantity,
                    products.unitprice AS unit_price
                FROM warehouse
                JOIN products ON warehouse.productid = products.productid
                WHERE warehouse.warehouseid = %s;
            """, (user_id,))
            warehouse_reports = cur.fetchall()

            if not warehouse_reports:
                flash("No products found in the warehouse.", "warning")

            return render_template('warehouse_reports.html', warehouse_reports=warehouse_reports)
    except Exception as e:
        flash(f"An error occurred while fetching warehouse reports: {e}", "danger")
        return redirect(url_for("warehouse_dashboard"))




@app.route('/Orders_and_shipment_reports')
def Orders_and_shipment_reports():
        return redirect(url_for('warehouse_dashboard'))


# 4. تتبع الشحنات (Track Shipments)
@app.route('/track_shipments')
def track_shipments():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT 
                shipping.shippingid, 
                shipping.orderid, 
                shipping.shippingstatus AS status, 
                shipping.shippingdate
            FROM shipping;
        """)

        shipments = cur.fetchall()
        return render_template('track_shipments.html', shipments=shipments)
    except Exception as e:
        return f"حدث خطأ أثناء جلب بيانات الشحنات: {e}", 500
    finally:
        conn.close()





@app.route('/view_current_warehouse')
def view_current_warehouse():
    return redirect(url_for('warehouse_dashboard'))

@app.route('/update_product_quantities')
def update_product_quantities():
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


@app.route('/manage_returns')
def manage_returns():
    return redirect(url_for('warehouse_dashboard'))


@app.route('/analyze_warehouse_turnover')
def analyze_warehouse_turnover():
    return redirect(url_for('warehouse_dashboard'))






@app.route("/logout_users")
def logout_users():
    session.clear()  # حذف جميع بيانات الجلسة
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))




@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # استلام البيانات من النموذج
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
                    # لا حاجة لإدخال بيانات إضافية هنا
                    pass

                elif role == "warehouse_staff":
                    print(f"Registering sales_staff with user_id: {user_id}")
                    # لا حاجة لإدخال بيانات إضافية هنا
                    pass


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
