from tkinter import *
from tkinter import messagebox
from tkinter import ttk
import sqlite3
import hashlib
import random
import os
from datetime import datetime


class ModernSupermarket:
    def __init__(self, root):
        self.root = root
        self.root.geometry("1400x800+50+50")
        self.root.title("نظام إدارة السوبر ماركت الضلاع")
        self.root.resizable(False, False)
        self.root.configure(bg="#2c3e50")
        self.root.protocol("WM_DELETE_WINDOW", self.root.destroy)

        self.init_database()

        # Current user
        self.current_user = None

        # Show login screen
        self.show_login()

    def init_database(self):
        """Initialize SQLite database for users"""
        self.conn = sqlite3.connect("supermarket.db")
        self.cursor = self.conn.cursor()

        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                full_name TEXT NOT NULL,
                email TEXT,
                role TEXT DEFAULT 'cashier',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """
        )

        admin_password = hashlib.sha256("admin123".encode()).hexdigest()
        try:
            self.cursor.execute(
                """
                INSERT INTO users (username, password, full_name, role)
                VALUES (?, ?, ?, ?)
            """,
                ("admin", admin_password, "مدير النظام", "admin"),
            )
            self.conn.commit()
        except sqlite3.IntegrityError:
            pass

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def show_login(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        self.root.configure(bg="#2c3e50")

        main_frame = Frame(self.root, bg="#2c3e50")
        main_frame.pack(fill=BOTH, expand=True)

        title_label = Label(
            main_frame,
            text="🛒 نظام إدارة السوبر ماركت الضلاع",
            font=("Tajawal", 26, "bold"),
            fg="#ecf0f1",
            bg="#2c3e50",
            height=2,
        )
        title_label.pack(fill=X, pady=(0, 30))

        shadow = Frame(main_frame, bg="#2c3e50")
        shadow.place(relx=0.5, rely=0.5, anchor=CENTER, width=460, height=510)

        login_frame = Frame(main_frame, bg="#34495e")
        login_frame.place(relx=0.5, rely=0.5, anchor=CENTER, width=450, height=500)
        login_frame.lift()

        Label(
            login_frame,
            text="تسجيل الدخول",
            font=("Tajawal", 22, "bold"),
            bg="#34495e",
            fg="#ecf0f1",
        ).pack(pady=(25, 40))

        Label(
            login_frame,
            text="اسم المستخدم:",
            font=("Tajawal", 12),
            bg="#34495e",
            fg="#bdc3c7",
        ).pack(anchor=E, padx=40)
        self.username_var = StringVar()
        Entry(
            login_frame,
            textvariable=self.username_var,
            font=("Tajawal", 12),
            bg="#2c3e50",
            fg="#ecf0f1",
            bd=0,
            relief=FLAT,
            insertbackground="#ecf0f1",
        ).pack(pady=(5, 20), ipady=8)

        Label(
            login_frame,
            text="كلمة المرور:",
            font=("Tajawal", 12),
            bg="#34495e",
            fg="#bdc3c7",
        ).pack(anchor=E, padx=40)
        self.password_var = StringVar()
        Entry(
            login_frame,
            textvariable=self.password_var,
            font=("Tajawal", 12),
            bg="#2c3e50",
            fg="#ecf0f1",
            bd=0,
            show="*",
            relief=FLAT,
            insertbackground="#ecf0f1",
        ).pack(pady=(5, 30), ipady=8)

        Button(
            login_frame,
            text="دخول",
            font=("Tajawal", 14, "bold"),
            bg="#27ae60",
            fg="white",
            bd=0,
            relief=FLAT,
            width=20,
            command=self.login,
            cursor="hand2",
        ).pack(pady=10, ipady=8, ipadx=8)

        Button(
            login_frame,
            text="إنشاء حساب جديد",
            font=("Tajawal", 14, "bold"),
            bg="#3498db",
            fg="white",
            bd=0,
            relief=FLAT,
            width=20,
            command=self.show_register,
            cursor="hand2",
        ).pack(pady=10, ipady=8, ipadx=8)

        self.root.bind("<Return>", lambda e: self.login())
        self.username_var.set("")
        self.password_var.set("")

    def show_register(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        self.root.configure(bg="#2c3e50")

        main_frame = Frame(self.root, bg="#2c3e50")
        main_frame.pack(fill=BOTH, expand=True)

        title_label = Label(
            main_frame,
            text="إنشاء حساب جديد",
            font=("Tajawal", 26, "bold"),
            fg="#ecf0f1",
            bg="#2c3e50",
            height=2,
        )
        title_label.pack(fill=X, pady=(0, 30))

        register_frame = Frame(main_frame, bg="#34495e")
        register_frame.place(relx=0.5, rely=0.5, anchor=CENTER, width=500, height=600)

        fields = [
            ("الاسم الكامل:", "full_name"),
            ("اسم المستخدم:", "reg_username"),
            ("البريد الإلكتروني:", "email"),
            ("كلمة المرور:", "reg_password"),
            ("تأكيد كلمة المرور:", "confirm_password"),
        ]

        self.register_vars = {}

        for label_text, var_name in fields:
            Label(
                register_frame,
                text=label_text,
                font=("Tajawal", 12),
                bg="#34495e",
                fg="#bdc3c7",
            ).pack(anchor=E, padx=50, pady=(15, 5))
            self.register_vars[var_name] = StringVar()
            entry = Entry(
                register_frame,
                textvariable=self.register_vars[var_name],
                font=("Tajawal", 12),
                bg="#2c3e50",
                fg="#ecf0f1",
                bd=0,
                relief=FLAT,
                insertbackground="#ecf0f1",
            )
            if "password" in var_name:
                entry.config(show="*")
            entry.pack(pady=(0, 10), ipady=8)

        btn_frame = Frame(register_frame, bg="#34495e")
        btn_frame.pack(pady=30)

        Button(
            btn_frame,
            text="إنشاء الحساب",
            font=("Tajawal", 14, "bold"),
            bg="#27ae60",
            fg="white",
            bd=0,
            relief=FLAT,
            width=15,
            command=self.register,
            cursor="hand2",
        ).pack(side=LEFT, padx=10, ipady=8)

        Button(
            btn_frame,
            text="العودة",
            font=("Tajawal", 14),
            bg="#e74c3c",
            fg="white",
            bd=0,
            relief=FLAT,
            width=15,
            command=self.show_login,
            cursor="hand2",
        ).pack(side=LEFT, padx=10, ipady=8)

        self.root.unbind("<Return>")

    def login(self):
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()

        if not username or not password:
            messagebox.showerror("خطأ", "يرجى ملء جميع الحقول")
            return

        hashed_password = self.hash_password(password)
        self.cursor.execute(
            """
            SELECT id, username, full_name, role FROM users 
            WHERE username = ? AND password = ?
        """,
            (username, hashed_password),
        )

        user = self.cursor.fetchone()

        if user:
            self.current_user = {
                "id": user[0],
                "username": user[1],
                "full_name": user[2],
                "role": user[3],
            }
            self.root.unbind("<Return>")
            messagebox.showinfo("نجاح", f"مرحباً {self.current_user['full_name']}")
            self.show_main_system()
        else:
            messagebox.showerror("خطأ", "اسم المستخدم أو كلمة المرور غير صحيحة")

    def register(self):
        full_name = self.register_vars["full_name"].get().strip()
        username = self.register_vars["reg_username"].get().strip()
        email = self.register_vars["email"].get().strip()
        password = self.register_vars["reg_password"].get().strip()
        confirm_password = self.register_vars["confirm_password"].get().strip()

        if not all([full_name, username, password, confirm_password]):
            messagebox.showerror("خطأ", "يرجى ملء جميع الحقول المطلوبة")
            return

        if password != confirm_password:
            messagebox.showerror("خطأ", "كلمة المرور غير متطابقة")
            return

        if len(password) < 6:
            messagebox.showerror("خطأ", "كلمة المرور يجب أن تكون 6 أحرف على الأقل")
            return

        self.cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if self.cursor.fetchone():
            messagebox.showerror("خطأ", "اسم المستخدم موجود بالفعل")
            return

        hashed_password = self.hash_password(password)
        try:
            self.cursor.execute(
                """
                INSERT INTO users (username, password, full_name, email)
                VALUES (?, ?, ?, ?)
            """,
                (username, hashed_password, full_name, email),
            )
            self.conn.commit()
            messagebox.showinfo("نجاح", "تم إنشاء الحساب بنجاح!")
            self.show_login()
        except Exception as e:
            messagebox.showerror("خطأ", f"حدث خطأ في إنشاء الحساب: {str(e)}")

    def show_main_system(self):
        """Display the main supermarket system"""
        for widget in self.root.winfo_children():
            widget.destroy()
        self.root.configure(bg="#ecf0f1")
        self.init_variables()
        self.create_navbar()
        self.create_main_content()
        self.welcome()

    def init_variables(self):
        self.q_vars = {}
        self.product_data = {
            "groceries": [
                ("الرز", 1.5),
                ("برغل", 0.5),
                ("فاصولياء", 1.0),
                ("عدس", 1.5),
                ("معكرونة", 2.0),
                ("فريكة", 2.0),
                ("حمص", 1.0),
                ("فول", 1.0),
                ("ملح", 1.5),
                ("سكر", 1.0),
                ("فلفل أسود", 1.5),
                ("فلفل أحمر", 1.0),
                ("لوبيا", 1.5),
                ("إدمامي", 1.0),
                ("قمح", 2.0),
                ("شعير", 1.0),
                ("شوفان", 2.0),
                ("ذرة", 1.5),
            ],
            "household": [
                ("مصفاة", 5.0),
                ("صحن", 2.5),
                ("كأس", 1.0),
                ("ابريق", 10.0),
                ("سكين", 3.0),
                ("شوك", 1.5),
                ("طنجرة", 20.0),
                ("سلة", 7.0),
                ("ملاعق", 2.0),
                ("صينية", 8.0),
                ("وعاء الخلط", 12.0),
                ("فتاحة علب", 4.0),
                ("مقشرة", 3.5),
                ("لوح التقطيع", 6.0),
                ("حفارة", 5.5),
                ("سلة قمامة", 9.0),
                ("منفضة", 2.0),
                ("اكياس", 1.0),
            ],
            "electronics": [
                ("مكنسة", 150.0),
                ("تلفزيون", 500.0),
                ("غسالة", 700.0),
                ("مكرويف", 120.0),
                ("خلاط", 60.0),
                ("فرن غاز", 300.0),
                ("مقلاة كهرباء", 80.0),
                ("مروحة سقف", 90.0),
                ("مروحة ارضية", 70.0),
                ("تلفزيون 32", 250.0),
                ("تلفزيون 43", 400.0),
                ("فلتر ماء", 40.0),
                ("غسالة اوتو", 850.0),
                ("مكواة", 30.0),
                ("مبردة", 180.0),
            ],
            "drinks": [
                ("ماء", 0.5),
                ("عصير برتقال", 1.2),
                ("كولا", 1.0),
                ("حليب", 1.5),
                ("شاي", 0.8),
                ("قهوة", 2.0),
            ],
            "sweet": [
                ("شوكولاتة", 2.5),
                ("بسكويت", 1.0),
                ("كيك", 5.0),
                ("حلوى", 0.75),
                ("آيس كريم", 3.0),
            ],
        }
        for category, products in self.product_data.items():
            for i, (name, price) in enumerate(products):
                self.q_vars[f"{category}_{i}"] = IntVar(value=0)

        self.bacoliat = StringVar()
        self.adoat = StringVar()
        self.kahraba = StringVar()
        self.grand_total_var = StringVar()

        self.nemo = StringVar()
        self.phono = StringVar()
        self.fatora = StringVar()
        self.fatora.set(str(random.randint(1000, 9999)))
        self.searcho = StringVar()

        self.shopping_cart = []

    def create_navbar(self):
        navbar = Frame(self.root, bg="#2c3e50", height=80)
        navbar.pack(fill=X)
        navbar.pack_propagate(False)
        logo_frame = Frame(navbar, bg="#2c3e50")
        logo_frame.pack(side=LEFT, padx=20, pady=15)
        Label(
            logo_frame, text="🛒", font=("Arial", 24), bg="#2c3e50", fg="#ecf0f1"
        ).pack(side=LEFT)
        Label(
            logo_frame,
            text="سوبر ماركت الضلاع",
            font=("Arial", 18, "bold"),
            bg="#2c3e50",
            fg="#ecf0f1",
        ).pack(side=LEFT, padx=(10, 0))
        user_frame = Frame(navbar, bg="#2c3e50")
        user_frame.pack(side=RIGHT, padx=20, pady=15)
        Label(
            user_frame,
            text=f'مرحباً، {self.current_user["full_name"]}',
            font=("Arial", 12),
            bg="#2c3e50",
            fg="#bdc3c7",
        ).pack(side=RIGHT)
        Button(
            user_frame,
            text="تسجيل خروج",
            font=("Arial", 10),
            bg="#e74c3c",
            fg="white",
            bd=0,
            relief=FLAT,
            command=self.logout,
            cursor="hand2",
        ).pack(side=RIGHT, padx=(0, 15), ipady=5, ipadx=10)
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M")
        Label(
            user_frame,
            text=current_time,
            font=("Arial", 10),
            bg="#2c3e50",
            fg="#95a5a6",
        ).pack(side=RIGHT, padx=(0, 15))

    def create_main_content(self):
        main_container = Frame(self.root, bg="#ecf0f1")
        main_container.pack(fill=BOTH, expand=True, padx=10, pady=10)
        left_frame = Frame(main_container, bg="#ecf0f1")
        left_frame.pack(side=LEFT, fill=BOTH, expand=True)
        right_frame = Frame(main_container, bg="#ecf0f1", width=400)
        right_frame.pack(side=RIGHT, fill=Y, padx=(10, 0))
        right_frame.pack_propagate(False)
        self.create_product_sections(left_frame)
        self.create_customer_section(right_frame)
        self.create_bill_section(right_frame)
        self.create_total_section(right_frame)

    def add_to_cart(self, category, index):
        product_name, price = self.product_data[category][index]
        quantity_var = self.q_vars[f"{category}_{index}"]
        quantity = quantity_var.get()
        if quantity > 0:
            item_found = False
            for item in self.shopping_cart:
                if item[0] == product_name:
                    item[1] += quantity
                    item_found = True
                    break
            if not item_found:
                self.shopping_cart.append([product_name, quantity, price])
            messagebox.showinfo(
                "تم الإضافة", f"{quantity} من {product_name} تم إضافتها إلى السلة."
            )
            quantity_var.set(0)
            self.update_bill_display()
        else:
            messagebox.showwarning("تحذير", "الرجاء إدخال كمية أكبر من صفر.")

    def update_bill_display(self):
        self.txtarea.delete(1.0, END)
        self.welcome()
        current_total = 0
        for item in self.shopping_cart:
            product_name, quantity, price = item
            item_total = quantity * price
            self.txtarea.insert(
                END, f"{product_name}\t\t{quantity}\t\t{item_total:.2f}\n"
            )
            current_total += item_total
        self.txtarea.insert(END, "\n=========================================")
        self.txtarea.insert(END, f"\nالمجموع الكلي:\t\t\t${current_total:.2f}")
        self.txtarea.insert(END, "\n=========================================")
        self.grand_total_var.set(f"${current_total:.2f}")

    def create_product_sections(self, parent):
        notebook = ttk.Notebook(parent)
        notebook.pack(fill=BOTH, expand=True)
        style = ttk.Style()
        style.configure("TNotebook.Tab", padding=[20, 10])
        categories = [
            ("البقوليات", "groceries"),
            ("اللوازم المنزلية", "household"),
            ("الأجهزة الكهربائية", "electronics"),
            ("مشروبات", "drinks"),
            ("حلويات", "sweet"),
        ]
        for tab_name, category_key in categories:
            frame = Frame(notebook, bg="#f4f6f7")
            notebook.add(frame, text=tab_name)
            self.create_product_tab(frame, category_key)

    def create_product_tab(self, parent, category_key):
        # Canvas + Scroll
        canvas = Canvas(parent, bg="#f4f6f7", highlightthickness=0)
        scrollbar = Scrollbar(parent, orient=VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)

        scrollable_frame = Frame(canvas, bg="#f4f6f7")
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

        def on_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))

        scrollable_frame.bind("<Configure>", on_configure)

        # تخطيط أعمدة مرن: 3 أعمدة افتراضيًا
        columns = 3
        if category_key == "groceries":
            columns = 3  # يمكنك تغييرها إلى 2 إذا رغبت بحجم أكبر
        for c in range(columns):
            scrollable_frame.columnconfigure(c, weight=1, uniform="col")

        products = self.product_data[category_key]

        for i, (name, price) in enumerate(products):
            row = i // columns
            col = i % columns

            # بطاقة كبيرة وأنيقة
            card = Frame(
                scrollable_frame,
                bg="#ffffff",
                bd=0,
                highlightthickness=1,
                highlightbackground="#e0e0e0",
            )
            card.grid(row=row, column=col, padx=12, pady=12, sticky="nsew")
            card.configure(width=260, height=180)
            card.grid_propagate(False)

            # رأس البطاقة: اسم + شارة السعر
            header = Frame(card, bg="#ffffff")
            header.pack(fill=X, padx=12, pady=(12, 6))
            Label(
                header,
                text=name,
                font=("Tajawal", 14, "bold"),
                bg="#ffffff",
                fg="#2c3e50",
            ).pack(side=RIGHT)
            price_badge = Label(
                header,
                text=f"${price:.2f}",
                font=("Tajawal", 12, "bold"),
                bg="#eafaf1",
                fg="#27ae60",
                bd=1,
                relief=GROOVE,
                padx=10,
                pady=3,
            )
            price_badge.pack(side=LEFT)

            # فاصل بسيط
            Frame(card, bg="#f0f0f0", height=1).pack(fill=X, padx=12, pady=4)

            # منطقة التحكم بالكمية
            qty_frame = Frame(card, bg="#ffffff")
            qty_frame.pack(pady=10)

            qvar = self.q_vars[f"{category_key}_{i}"]

            def dec(var=qvar):
                current = var.get()
                if current > 0:
                    var.set(current - 1)

            def inc(var=qvar):
                var.set(var.get() + 1)

            btn_style = {
                "font": ("Tajawal", 12, "bold"),
                "bd": 0,
                "relief": FLAT,
                "cursor": "hand2",
            }
            Button(
                qty_frame,
                text="−",
                width=3,
                bg="#ecf0f1",
                fg="#2c3e50",
                command=dec,
                **btn_style,
            ).pack(side=RIGHT, padx=(0, 6))
            qty_entry = Entry(
                qty_frame,
                textvariable=qvar,
                font=("Tajawal", 12),
                width=6,
                justify="center",
                bd=1,
                relief=SOLID,
            )
            qty_entry.pack(side=RIGHT)
            Button(
                qty_frame,
                text="+",
                width=3,
                bg="#ecf0f1",
                fg="#2c3e50",
                command=inc,
                **btn_style,
            ).pack(side=RIGHT, padx=(6, 0))

            # زر الإضافة ممتد أسفل البطاقة
            add_btn = Button(
                card,
                text="أضف إلى السلة",
                font=("Tajawal", 12, "bold"),
                bg="#27ae60",
                fg="white",
                bd=0,
                relief=FLAT,
                command=lambda cat=category_key, idx=i: self.add_to_cart(cat, idx),
                cursor="hand2",
            )
            add_btn.pack(fill=X, padx=12, pady=(8, 12), ipady=6)

        # توسيع آخر صف عموديًا قليلاً
        last_row = (len(products) - 1) // columns
        scrollable_frame.rowconfigure(last_row, weight=0)

        # عند تغيير حجم الـ parent، نجعل عرض الكانفس يساوي عرضه لتجنب قص البطاقات
        def on_parent_resize(event):
            canvas.itemconfig(canvas.find_all()[0], width=event.width)

        canvas.bind("<Configure>", on_parent_resize)

    def create_customer_section(self, parent):
        F1 = Frame(parent, bd=2, width=338, height=170, bg="#0B4C5F")
        F1.pack(pady=(0, 10), fill=X)
        Label(
            F1,
            text=": بيانات المشتري ",
            font=("Arial", 13, "bold"),
            bg="#0B4C5F",
            fg="tomato",
        ).place(x=185, y=0)
        Label(
            F1, text="اسم المشتري", font=("Arial", 10), bg="#0B4C5F", fg="white"
        ).place(x=230, y=40)
        Entry(F1, justify="center", textvariable=self.nemo).place(x=90, y=42)
        Label(
            F1, text="رقم المشتري", font=("Arial", 10), bg="#0B4C5F", fg="white"
        ).place(x=235, y=70)
        Entry(F1, justify="center", textvariable=self.phono).place(x=90, y=72)
        Label(
            F1, text="رقم الفاتورة", font=("Arial", 10), bg="#0B4C5F", fg="white"
        ).place(x=242, y=100)
        Entry(F1, justify="center", textvariable=self.fatora).place(x=90, y=102)
        Button(
            F1,
            text="بحث",
            font=("Arial", 10),
            width=10,
            height=2,
            bg="white",
            command=self.find,
        ).place(x=3, y=40)
        Label(
            F1, text="[ الفواتير ]", font=("Arial", 13, "bold"), bg="#0B4C5F", fg="gold"
        ).place(x=125, y=135)

    def create_bill_section(self, parent):
        F3 = Frame(parent, bd=2, bg="white")
        F3.pack(pady=(0, 10), fill=BOTH, expand=True)
        scrol_y = Scrollbar(F3, orient=VERTICAL)
        self.txtarea = Text(F3, yscrollcommand=scrol_y.set, font=("Consolas", 10))
        scrol_y.pack(side=RIGHT, fill=Y)
        scrol_y.config(command=self.txtarea.yview)
        self.txtarea.pack(fill=BOTH, expand=1)

    def create_total_section(self, parent):
        F4 = Frame(parent, bd=2, height=112, bg="#0B4C5F")
        F4.pack(fill=X)
        Button(
            F4,
            text="الحساب",
            width=13,
            height=1,
            font=("Arial", 10, "bold"),
            bg="#DBA901",
            command=self.total,
        ).place(x=250, y=10)
        Button(
            F4,
            text="تصدير فاتورة",
            width=13,
            height=1,
            font=("Arial", 10, "bold"),
            bg="#DBA901",
            command=self.billing,
        ).place(x=250, y=55)
        Button(
            F4,
            text="افراغ الحقول",
            width=13,
            height=1,
            font=("Arial", 10, "bold"),
            bg="#DBA901",
            command=self.clear,
        ).place(x=100, y=10)
        Button(
            F4,
            text="اغلاق البرنامج",
            width=13,
            height=1,
            font=("Arial", 10, "bold"),
            bg="#DBA901",
            command=self.root.destroy,
        ).place(x=100, y=55)

        Label(
            F4,
            text="الإجمالي الكلي:",
            font=("Arial", 12, "bold"),
            bg="#0B4C5F",
            fg="white",
        ).place(x=20, y=85)
        Entry(
            F4,
            width=15,
            textvariable=self.grand_total_var,
            state="readonly",
            font=("Arial", 10, "bold"),
            justify="center",
        ).place(x=150, y=85)

    def welcome(self):
        self.txtarea.delete(1.0, END)
        self.txtarea.insert(END, "\t\tمرحباً بك في سوبر ماركت الضلاع\n")
        self.txtarea.insert(END, "\t\t\tفاتورة العميل\n")
        self.txtarea.insert(END, f"\nرقم الفاتورة:\t\t{self.fatora.get()}")
        self.txtarea.insert(END, f"\nاسم العميل:\t\t{self.nemo.get()}")
        self.txtarea.insert(END, f"\nرقم الهاتف:\t\t{self.phono.get()}")
        self.txtarea.insert(END, "\n=========================================")
        self.txtarea.insert(END, "\nالمنتج\t\tالكمية\t\tالسعر")
        self.txtarea.insert(END, "\n=========================================\n")

    def total(self):
        total_groceries_price = 0
        total_household_price = 0
        total_electronics_price = 0
        total_drinks_price = 0
        total_sweet_price = 0

        for name, quantity, price in self.shopping_cart:
            category_found = False
            for category, products in self.product_data.items():
                if any(name == n for n, _ in products):
                    if category == "groceries":
                        total_groceries_price += quantity * price
                    elif category == "household":
                        total_household_price += quantity * price
                    elif category == "electronics":
                        total_electronics_price += quantity * price
                    elif category == "drinks":
                        total_drinks_price += quantity * price
                    elif category == "sweet":
                        total_sweet_price += quantity * price
                    category_found = True
                    break
            if not category_found:
                print(f"Warning: Product '{name}' not found in any category.")

        self.bacoliat.set(f"${total_groceries_price:.2f}")
        self.adoat.set(f"${total_household_price:.2f}")
        self.kahraba.set(f"${total_electronics_price:.2f}")

        g_total = (
            total_groceries_price
            + total_household_price
            + total_electronics_price
            + total_drinks_price
            + total_sweet_price
        )
        self.grand_total_var.set(f"${g_total:.2f}")
        self.update_bill_display()

    def billing(self):
        if self.nemo.get() == "" or self.phono.get() == "":
            messagebox.showerror("خطأ", "يرجى ملء بيانات العميل (الاسم ورقم الهاتف)")
            return
        self.update_bill_display()
        bill_filename = f"bills/{self.fatora.get()}.txt"
        if not os.path.exists("bills"):
            os.makedirs("bills")
        with open(bill_filename, "w", encoding="utf-8") as f:
            f.write(self.txtarea.get(1.0, END))
        messagebox.showinfo("نجاح", f"تم حفظ الفاتورة بنجاح في {bill_filename}")

    def clear(self):
        for var in self.q_vars.values():
            var.set(0)
        self.shopping_cart = []
        self.bacoliat.set("")
        self.adoat.set("")
        self.kahraba.set("")
        self.grand_total_var.set("")
        self.nemo.set("")
        self.phono.set("")
        self.fatora.set(str(random.randint(1000, 9999)))
        self.welcome()

    def find(self):
        bill_no = self.searcho.get()
        if not bill_no:
            messagebox.showwarning("تحذير", "الرجاء إدخال رقم الفاتورة للبحث.")
            return

        bill_filename = f"bills/{bill_no}.txt"
        if os.path.exists(bill_filename):
            with open(bill_filename, "r", encoding="utf-8") as f:
                bill_content = f.read()
            self.txtarea.delete(1.0, END)
            self.txtarea.insert(END, bill_content)
            # Extract customer info from bill content
            try:
                lines = bill_content.split("\n")
                bill_num_line = next(line for line in lines if "رقم الفاتورة:" in line)
                customer_name_line = next(
                    line for line in lines if "اسم العميل:" in line
                )
                customer_phone_line = next(
                    line for line in lines if "رقم الهاتف:" in line
                )

                bill_num = bill_num_line.split("\t\t")[1]
                customer_name = customer_name_line.split("\t\t")[1]
                customer_phone = customer_phone_line.split("\t\t")[1]

                self.fatora.set(bill_num)
                self.nemo.set(customer_name)
                self.phono.set(customer_phone)
            except (StopIteration, IndexError) as e:
                print(f"Error parsing bill file: {e}")
                messagebox.showerror("خطأ", "حدث خطأ أثناء قراءة بيانات الفاتورة.")

            messagebox.showinfo("بحث", f"تم العثور على الفاتورة رقم {bill_no}.")
        else:
            messagebox.showerror("خطأ", f"الفاتورة رقم {bill_no} غير موجودة.")

    def logout(self):
        self.current_user = None
        self.show_login()


if __name__ == "__main__":
    root = Tk()
    app = ModernSupermarket(root)
    root.mainloop()
