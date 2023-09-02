from flask import *
from flask_mysqldb import *
from wtforms import *
from functools import *
from flask_wtf import *
from wtforms.validators import *
from flask_mail import *
import hashlib
import uuid
from email.mime.text import MIMEText
import smtplib
import ssl
from email.message import EmailMessage
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash


app = Flask(__name__)


app.secret_key = "firstblog"
app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = ""
app.config["MYSQL_DB"] = "firstblog"
app.config["MYSQL_CURSORCLASS"] = "DictCursor"
app.config["SECRET_KEY"] = "your_secret_key"
app.charset = "utf-8"


mysql = MySQL(app)


# kullanıcı girişi decorator'ı
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" in session:
            return f(*args, **kwargs)
        else:
            flash("Bu Sayfayı Görüntülemek İçin Lütfen Giriş Yapın", "danger")
            return redirect(url_for("login"))

    return decorated_function


class RegisterForm(Form):
    name = StringField("İsim Soyisim", [validators.Length(min=4, max=25)])
    username = StringField("Kullanıcı Adı", [validators.Length(min=5, max=32)])
    email = StringField(
        "E-posta Adresi",
        [
            validators.Email(message="Lütfen E-posta Adresinizi Kontrol Edin"),
            validators.DataRequired(),
        ],
    )
    password = PasswordField(
        "Parola:",
        [
            validators.DataRequired(),
            validators.EqualTo("confirm", message="Parolanız Uyuşmuyor"),
        ],
    )
    confirm = PasswordField("Parola Doğrula")


class LoginForm(Form):
    username = StringField("Kullanıcı Adınız:")
    password = PasswordField("Şifreniz:")


class ResetForm(FlaskForm):
    email = StringField("E-posta Adresi", validators=[DataRequired(), Email()])
    submit = SubmitField("Gönder")


class PasswordResetForm(FlaskForm):
    password = PasswordField("Yeni Şifre", validators=[DataRequired()])
    password2 = PasswordField(
        "Yeni Şifre Tekrar", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("Şifreyi Güncelle")


class ArticleForm(Form):
    title = TextAreaField("Makale Başlığı", validators=[DataRequired()])

    content = TextAreaField(
        "Makale İçeriği", validators=[DataRequired(), Length(min=10)]
    )


class CevapVer(Form):
    icerik = TextAreaField("Yorum İçeriği", validators=[DataRequired()])


@app.route("/")
def index():
    information = [
        {"id": 1, "name": "python1", "content": "flask1"},
        {"id": 2, "name": "python2", "content": "flask2"},
        {"id": 3, "name": "python3", "content": "flask3"},
    ]
    return render_template("index.html", information=information)


@app.route("/x-index")
def index2():
    return render_template("x-index.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.errorhandler(404)
def page_not_found(e):
    return render_template("error.html"), 404


@app.route("/dashboard")
@login_required
def dashboard():
    cursor = mysql.connection.cursor()
    sorgu = "Select * From articles where author=%s"

    result = cursor.execute(sorgu, (session["username"],))

    if result > 0:
        articles = cursor.fetchall()
        return render_template("dashboard.html", articles=articles)
    else:
        return render_template("dashboard.html")
    
    

    return render_template("dashboard.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm(request.form)
    if request.method == "POST" and form.validate():
        name = form.name.data
        username = form.username.data
        email = form.email.data
        password = form.password.data
        hashed = hashlib.sha256(password.encode()).hexdigest()

        # Check if the username is already taken
        cursor = mysql.connection.cursor()
        sorgu = "SELECT * FROM users WHERE username = %s"
        result = cursor.execute(sorgu, (username,))
        if result > 0:
            flash(
                "Bu kullanıcı adı zaten alınmış, lütfen farklı bir kullanıcı adı seçin",
                "danger",
            )
            return redirect(url_for("register"))

        sorgu = (
            "INSERT INTO users(name, username, email, password) VALUES (%s, %s, %s, %s)"
        )
        cursor.execute(sorgu, (name, username, email, hashed))
        mysql.connection.commit()
        cursor.close()

        flash("Başarıyla Kayıt Oldunuz", "success")
        return redirect(url_for("index"))
    else:
        return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm(request.form)
    if request.method == "POST" and form.validate():
        username = form.username.data
        password = form.password.data
        cursor = mysql.connection.cursor()
        sorgu = "Select * From users where username = %s"
        result = cursor.execute(sorgu, (username,))
        if result > 0:
            data = cursor.fetchone()
            saved_password = data["password"]
            if hashlib.sha256(password.encode()).hexdigest() == saved_password:
                session["logged_in"] = True
                session["username"] = username
                flash("Başarıyla Giriş Yaptınız", "success")
                return redirect(url_for("index"))
            else:
                flash("Parolanızı yanlış girdiniz, lütfen tekrar deneyin", "danger")
        else:
            flash("Böyle bir kullanıcı bulunmuyor", "danger")
        cursor.close()
    return render_template("login.html", form=form)


@app.route("/reset", methods=["GET", "POST"])
def reset():
    form = ResetForm()
    if form.validate_on_submit():
        email_sender = "cancoderx@gmail.com"
        email_password = "wmwvlwfbaizzidfy"
        email_receiver = form.email.data

        s = URLSafeTimedSerializer("your_secret_key")
        token = s.dumps(email_receiver, salt="reset-password")
        reset_link = url_for("reset_password", token=token, _external=True)

        baslik = "Şifre yenileme isteği"
        body = f"Lütfen aşağıdaki linke tıklayarak şifrenizi yenileyin:\n{reset_link}"

        msg = EmailMessage()
        msg.set_content(body)

        msg["Subject"] = baslik
        msg["From"] = email_sender
        msg["To"] = email_receiver

        context = ssl.create_default_context()

        with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
            smtp.ehlo()
            smtp.starttls(context=context)
            smtp.ehlo()
            smtp.login(email_sender, email_password)
            smtp.send_message(msg)

        flash("Şifre sıfırlama bağlantısı e-posta adresinize gönderildi.", "success")
        return redirect(url_for("login"))

    return render_template("reset.html", form=form)


@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    form = PasswordResetForm()
    if request.method == "POST":
        print("merhaba")
        return render_template("new-password.html", form=form)


"""@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    form = PasswordResetForm()
    if form.validate_on_submit():
        email = form.email.data
        new_password = form.password.data
        password = generate_password_hash(new_password)
        conn = mysql.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE email = %s", (email,))
        result = cursor.fetchone()
        if result is not None:
            cursor.execute("UPDATE users SET password = %s WHERE email = %s", (password, email))
            if cursor.rowcount == 0:
                flash('Böyle bir kullanıcı bulunamadı.', 'danger')
                return redirect(url_for('reset_password'))
            
        else:
            flash('Böyle bir kullanıcı bulunamadı.', 'danger')
            return redirect(url_for('reset_password'))
        
        conn.commit()
        cursor.close()
        conn.close()
        flash('Şifreniz başarıyla değiştirildi.', 'success')
        return redirect(url_for('login'))
    return render_template("reset_password.html", form=form)
    
"""


# çıkış (log out) işlemi


@app.route("/logout")
def logout():
    session.clear()
    flash("Çıkış Yaptınız", "danger")
    return redirect(url_for("index"))


@app.route("/yorumlar/<string:article_title>/<int:article_id>", methods=["GET", "POST"])
def yorumlara_bak(article_title, article_id):
    cursor = mysql.connection.cursor()

    # Makale başlığını veritabanından çek
    cursor.execute("SELECT title, content FROM articles WHERE id = %s", (article_id,))
    makale = cursor.fetchone()

    if not makale:
        flash("Hata: Belirtilen makale bulunamadı.", "danger")
        return redirect(url_for("dashboard"))

    # Makale başlığını kullanarak ilgili yorumları çek
    cursor.execute("SELECT id, yorum FROM yorumlar WHERE baslik = %s", (article_title,))
    yorumlar = cursor.fetchall()
    cursor.close()


    return render_template("yorumlar.html", makale=makale, yorumlar=yorumlar)


@app.route("/yorum/<string:article_title>", methods=["GET", "POST"])
def yorum_ekle(article_title):
    form = CevapVer(request.form)

    cursor = mysql.connection.cursor()
    cursor.execute(
        "SELECT author,title FROM articles WHERE title = %s", (article_title,)
    )
    makale = cursor.fetchone()
    cursor.close()

    if makale is None:
        flash("Hata: Belirtilen başlık bulunamadı.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST" and form.validate():
        yorum_icerik = form.icerik.data
        cevaplayan = session["username"]
        cevaplanan = makale["author"]  # n yazarı
        baslik = makale["title"]

        # Yorumu veritabanına ekleyin
        cursor = mysql.connection.cursor()
        sorgu = "INSERT INTO yorumlar (yorum, cevaplayan, cevaplanan,baslik) VALUES (%s, %s, %s,%s)"
        cursor.execute(sorgu, (yorum_icerik, cevaplayan, cevaplanan, baslik))
        mysql.connection.commit()
        cursor.close()


        flash("Yorum başarıyla eklendi", "success")
        return redirect(url_for("dashboard"))

    return render_template("cevapla.html", article_title=article_title, form=form)


@app.route("/addarticle", methods=["GET", "POST"])
def addarticle():
    form = ArticleForm(request.form)
    if request.method == "POST" and form.validate():
        title = form.title.data
        content = form.content.data

        cursor = mysql.connection.cursor()

        sorgu = "insert into articles(title,author,content) values(%s,%s,%s)"
        name = session["username"]
        cursor.execute(sorgu, (title, name, content))

        mysql.connection.commit()

        cursor.close()
        flash("Makale Başarıyla Eklendi", "success")

        return redirect(url_for("dashboard"))  # Yönlendirme işlemi burada yapılmalıdır.

    return render_template("addarticle.html", form=form)


# arama


@app.route("/search", methods=["GET", "POST"])
def search():
    if request.method == "GET":
        return redirect(url_for("index"))
    else:
        keyword = request.form.get("keyword")

        cursor = mysql.connection.cursor()

        sorgu = "Select * from articles where title like '%" + keyword + "%' "

        result = cursor.execute(sorgu)

        if result == 0:
            flash("Böyle Bir Makale Bulunmuyor", "warning")
            return redirect(url_for("articles"))
        else:
            articles = cursor.fetchall()

            return render_template("articles.html", articles=articles)


# makale değiştirme


@app.route("/edit/<string:id>", methods=["GET", "POST"])
@login_required
def update(id):
    if request.method == "GET":
        cursor = mysql.connection.cursor()

        sorgu = "Select * from articles where id=%s and author=%s"
        result = cursor.execute(sorgu, (id, session["username"]))

        if result == 0:
            flash("Böyle Bir Makale veya Buna Yetkiniz Yok", "danger")
            return redirect(url_for("index"))

        else:
            article = cursor.fetchone()
            form = ArticleForm()

            form.title.data = article["title"]
            form.content.data = article["content"]
            return render_template("update.html", form=form)
    else:
        form = ArticleForm(request.form)

        newTitle = form.title.data
        newContent = form.content.data

        sorgu2 = "Update articles set title=%s, content=%s where id=%s"

        cursor = mysql.connection.cursor()

        cursor.execute(sorgu2, (newTitle, newContent, id))

        mysql.connection.commit()

        flash("Makale Başarıyla Güncellendi", "success")

        return redirect(url_for("dashboard"))


# makale silme


@app.route("/delete/<string:id>")
@login_required
def delete(id):
    cursor = mysql.connection.cursor()
    sorgu = "Select * from articles where author=%s and id=%s"
    result = cursor.execute(sorgu, (session["username"], id))
    if result > 0:
        sorgu2 = "Delete from articles where id=%s"
        cursor.execute(sorgu2, (id,))

        mysql.connection.commit()
        flash("Makale Başarıyla Silindi", "success")
        return redirect(url_for("dashboard"))

    else:
        flash("Böyle Bir Makale veya Bu İşleme Yetkiniz Yok", "danger")
        return redirect(url_for("dashboard"))


@app.route("/articles")
def articles():
    cursor = mysql.connection.cursor()
    sorgu = "Select * From articles"

    result = cursor.execute(sorgu)

    if result > 0:
        articles = cursor.fetchall()
        return render_template("articles.html", articles=articles)

    else:
        return render_template("articles.html")


@app.route("/yorumlariniz")
def yorumlariniz():
    sorgu = "select yorum from yorumlar where cevaplayan=%s"
    cursor = mysql.connection.cursor()
    name = session["username"]
    result = cursor.execute(sorgu, (name,))

    if result > 0:
        yorumlar = cursor.fetchall()
        return render_template("yorumlariniz.html", yorumlar=yorumlar)
    else:
        return render_template("yorumlariniz.html")


@app.route("/article/<string:id>")
def article(id):
    cursor = mysql.connection.cursor()

    sorgu = "Select * from articles where id=%s"

    result = cursor.execute(sorgu, (id,))

    if result > 0:
        article = cursor.fetchone()
        return render_template("article.html", article=article)
    else:
        return render_template("article.html")


@app.route("/yorum/<int:id>")
def yorum(id):
    cursor = mysql.connection.cursor()

    sorgu = "Select * from yorumlar where id=%s"

    result = cursor.execute(sorgu, (id,))

    if result > 0:
        yorum = cursor.fetchone()
        return render_template("yorum.html", yorum=yorum)
    else:
        return render_template("yorum.html")


if __name__ == "__main__":
    app.run(debug=True)
