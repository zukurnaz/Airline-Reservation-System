# -*- coding: utf-8 -*-

from flask import Flask, redirect, url_for, render_template, request, session, flash
from datetime import timedelta,datetime
from pytz import timezone
import pytz
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
import hashlib, binascii, os

application = Flask(__name__)
application.secret_key = "hello"
application.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
application.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
application.permanent_session_lifetime = timedelta(minutes=10)
turkey = timezone('Europe/Istanbul')

db = SQLAlchemy(application)

class reservation(db.Model):
    rid = db.Column(db.Integer, primary_key=True)
    rdate = db.Column(db.DateTime, default=datetime.now(turkey))    
    ruid = db.Column(db.Integer)
    rflightid = db.Column(db.Integer)
    rseats = db.Column(db.Integer)
    rstatus = db.Column(db.Integer, default=0)


    def __init__(self, ruid, rflightid, rseats):
        self.ruid = ruid
        self.rflightid = rflightid
        self.rseats = rseats

class cities(db.Model):
    cid = db.Column(db.Integer, primary_key=True)
    cname = db.Column(db.String)
    
    def __init__(self,cname):
        self.cname = cname
    
class tickets(db.Model):
    tid = db.Column(db.Integer, primary_key=True)
    tfrom = db.Column(db.String(100))
    twhere = db.Column(db.String(100))
    tdate = db.Column(db.Date)
    ttime = db.Column(db.Integer)
    tetime = db.Column(db.Integer)
    tprice = db.Column(db.Integer)
    tseats = db.Column(db.Integer)
    taseats = db.Column(db.Integer)

    
    def __init__(self, tfrom,twhere,tdate,ttime,tetime,tprice,tseats,taseats):
        self.tfrom = tfrom
        self.twhere = twhere
        self.tdate = tdate
        self.ttime = ttime
        self.tetime = tetime
        self.tprice = tprice
        self.tseats = tseats
        self.taseats = taseats

class users(db.Model):
    uid = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    sname = db.Column(db.String(100))
    upwd = db.Column(db.String(100))
    email = db.Column(db.String(100))
    rank = db.Column(db.Integer)
    bonus = db.Column(db.Float)

    def __init__(self, name, email,upwd,sname,rank):
        self.name = name
        self.email = email
        self.upwd = upwd
        self.sname = sname
        self.rank = rank

def hash_password(password):
    """Hash a password for storing."""
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), 
                                salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')

def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user"""
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512', 
                                  provided_password.encode('utf-8'), 
                                  salt.encode('ascii'), 
                                  100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return pwdhash == stored_password

@application.route("/")
def home():
    return render_template("index.html")

@application.route("/admin")
def admin():
    if "admin" in session:
        varusers = users.query.order_by(users.uid).all() #veri tabanÄ±ndaki kullanÄ±cÄ±larÄ± alÄ±r.
        for user in varusers: #kullanÄ±cÄ±larÄ±n ÅŸifrelerini deÄŸiÅŸtirir (veritabanÄ±na yÃ¼klemez).
            user.upwd = "********" 
        return render_template("admin.html",varusers=varusers) #admin.html sayfasÄ±na kullanÄ±cÄ±larÄ± gÃ¶nderir.
    else : #admin session'da deÄŸilse yÃ¶nlendirme iÅŸlemi yapÄ±lÄ±r.
        flash("Admin sayfasÄ±nÄ± gÃ¶rÃ¼ntÃ¼leme izniniz yok!", "info") 
        return redirect(url_for("user"))

@application.route("/buyticket/<int:fid>", methods=["POST","GET"])
def buyticket(fid):
    if "email" in session: # kullanÄ±cÄ± giriÅŸi yapÄ±lmÄ±ÅŸsa
        if request.method == 'POST': # Form'da butona basÄ±lÄ±rsa
            flight = tickets.query.filter_by(tid=fid).first() # fid olarak gÃ¶nderilen uÃ§uÅŸ numarasÄ±nÄ± biletlerde ara
            if flight.taseats >= int(request.form["seatn"]): # formdaki yer uÃ§aktaki yerlerden fazla deÄŸilse
                user = users.query.filter_by(email=session["email"]).first() #kullanÄ±cÄ±yÄ± sessiondaki mailden bul
                userid = user.uid # kullanÄ±cÄ± id sini userid ye ata
                if request.form['action'] == 'Basket': # Action Basket ise 
                    res = reservation(userid,fid,int(request.form["seatn"])) # Rezervasyon oluÅŸtur
                    db.session.add(res) # veritabanÄ±na ekle
                    db.session.commit() # veritabanÄ±nÄ± kaydet
                    session["basket"] = reservation.query.filter_by(ruid=userid,rstatus=0).count() # Sepete eklenen Ã¼rÃ¼nlerin sayÄ±sÄ±nÄ± session basket'e aktar
                    flash("ÃœrÃ¼n sepetinize baÅŸarÄ±yla eklendi", "info")
                    return redirect(url_for("basket"))
                elif request.form['action'] == 'Buy':
                    inbonus = float(request.form["bonusn"]) # bonusn den kullanÄ±lmak istenen bonusu al
                    if inbonus > user.bonus: # kullanÄ±cÄ±nÄ±n bonusuyla kÄ±yasla
                        inbonus = user.bonus # kullanÄ±cÄ±nÄ±n bonusundan fazlaysa kullanÄ±cÄ± bonusunu kullanÄ±lmak istenenle deÄŸiÅŸtir
                    user.bonus -= inbonus # kullanÄ±lmak istenen bonusu kullanÄ±cÄ± bonusundan Ã§Ä±kart
                    res = reservation(userid,fid,int(request.form["seatn"])) #reservasyon oluÅŸtur
                    flight.taseats = flight.taseats-res.rseats # uÃ§aktaki boÅŸ koltuklardan rezervasyon koltuklarÄ±nÄ± Ã§Ä±kart
                    user.bonus += (flight.tprice * res.rseats) / 100*3 # kullanÄ±cÄ± bonusa 100de3 Ã¼ ekle
                    res.rstatus = 1 # rezervasyon statÃ¼sÃ¼nÃ¼ 1 olarak ayarla (satÄ±n alÄ±nmÄ±ÅŸ)
                    db.session.add(res) # veritabanÄ±na ekle
                    db.session.commit() # veritabanÄ±nÄ± gÃ¼ncelle
                    flash("SatÄ±n alma iÅŸleminiz baÅŸarÄ±yla gerÃ§ekleÅŸtirildi.", "info")
                    return redirect(url_for("reserve")) #rezervasyon sayfasÄ±na yÃ¶nlendir
            else:
                flash("UÃ§akta yeteri kadar yer yok!", "info") # yer yoksa uyarÄ± ver
                return redirect(url_for("buyticket",fid=fid))
    else : # giriÅŸ yapÄ±lmadÄ±ysa yÃ¶nlendir
        flash("LÃ¼tfen giriÅŸ yapÄ±nÄ±z", "info")
        return redirect(url_for("user"))
    flightnum = tickets.query.filter_by(tid=fid).first()
    user = users.query.filter_by(email=session["email"]).first()
    return render_template("buyticket.html",ticket=flightnum,user=user) # sayfaya bilgileri gÃ¶nder

@application.route("/emptybasket")
def emptybasket():
    if "email" in session:       
        currentuser = users.query.filter_by(email=session["email"]).first()
        reservations = reservation.query.filter_by(ruid=currentuser.uid,rstatus=0).all()
        for res in reservations:
            db.session.delete(res)
        db.session.commit()

        session["basket"] = reservation.query.filter_by(ruid=currentuser.uid,rstatus=0).count()  
      
        flash("Sepetiniz BaÅŸarÄ±yla Temizlendi")
        return redirect(url_for("order"))
    else:
        flash("LÃ¼tfen giriÅŸ yapÄ±nÄ±z", "info")
        return redirect(url_for("user"))

@application.route("/basket", methods=["POST","GET"])
def basket():
    if "email" in session:
        email = session["email"]
        currentuser = users.query.filter_by(email=email).first()
        ownerid = currentuser.uid
        if "basket" not in session: #basket yok ise veritabanÄ±ndaki statÃ¼sÃ¼ 0 olan verileri sil
            card = reservation.query.filter_by(ruid=ownerid,rstatus=0).all()
            for c in card:
                db.session.delete(c)
            db.session.commit()

        if request.method == 'POST':
            reserve = reservation.query.filter_by(rid=request.form['action']).first() #TamamlanÄ±cak rezervasyonu al
            flight = tickets.query.filter_by(tid=reserve.rflightid).first() # Rezervasyona ait UÃ§uÅŸ bilgilerini al
            if flight.taseats >= reserve.rseats: # Koltuk sayÄ±sÄ± yeterli ise
                flight.taseats = flight.taseats-reserve.rseats # UÃ§uÅŸtaki boÅŸ koltuk sayÄ±sÄ±ndan rezervasyondaki koltuk sayÄ±sÄ±nÄ± Ã§Ä±kart
                reserve.rstatus = 1 # Rezervasyon statÃ¼sÃ¼nÃ¼ Ã¶dendi olarak deÄŸiÅŸtir
                currentuser.bonus += (flight.tprice * reserve.rseats) / 100*3 # Ã¼cretin 100de 3 Ã¼nÃ¼ bonus olarak kullanÄ±cÄ±ya ekle
                db.session.commit() # veritabanÄ±nÄ± gÃ¼ncelle
                session["basket"] = reservation.query.filter_by(ruid=ownerid,rstatus=0).count() # sepetteki Ã¼rÃ¼nleri tekrar say
                flash("SatÄ±n alma iÅŸleminiz baÅŸarÄ±yla gerÃ§ekleÅŸti.", "info")
                return redirect(url_for("reserve"))
            else:
                db.session.delete(reserve) # uÃ§akta yer yok ise rezervasyonu sepetten sil ve sepeti baÅŸtan say
                db.session.commit()
                session["basket"] = reservation.query.filter_by(ruid=ownerid,rstatus=0).count()   
                flash("UÃ§akta yeteri kadar yer yok, iÅŸlem iptal edildi.", "info")
                return redirect(url_for("order"))
        session["basket"] = reservation.query.filter_by(ruid=ownerid,rstatus=0).count()
        
        reservations = reservation.query.filter_by(ruid=ownerid,rstatus=0).all()
        Name=currentuser.name + " " + currentuser.sname
        flights= tickets.query.order_by(tickets.tid).all()
        return render_template("basket.html", Reservation=reservations,Name=Name,flights=flights)
    else:
        flash("LÃ¼tfen GiriÅŸ YapÄ±n", "info")
        return redirect(url_for("user"))

@application.route("/order",methods=["POST","GET"])
def order():
    getcities = cities.query.order_by(cities.cid).all() 
    #Veri tabanÄ±ndan ÅŸehirleri getcities deÄŸiÅŸkenine aktarÄ±r
    currentdate = datetime.now(turkey).date() 
    #datetime kÃ¼tÃ¼phanesinden tarihi alÄ±r
    
    if request.method == 'POST' and request.form['action'] == 'Filtrele': 
        # Butona basÄ±lmasÄ± halinde tarihleri YÄ±l-ay-gÃ¼n ÅŸeklinde alÄ±r
        gtdate = datetime.strptime(request.form["gtdate"], '%Y-%m-%d').date()
        gtedate = datetime.strptime(request.form["gtedate"], '%Y-%m-%d').date()
        gtfrom,gtwhere = (request.form[s] for s in ('gtfrom', 'gtwhere')) 
        # Html formdan gtfrom,gtwhere (kalkÄ±ÅŸ varÄ±ÅŸ yerleri) deÄŸiÅŸkenlere aktarÄ±lÄ±r
        if gtdate < datetime.now(turkey).date(): 
            # Tarih geÃ§miÅŸe yÃ¶nelik ise hata verir
            flash("GeÃ§miÅŸ tarihe bilet alamazsÄ±nÄ±z!")
        else: 
            enddate=gtedate + timedelta(days=30) 
            # Belirtilen tarihten 30 gÃ¼n Ã¶ncesi ve sonrasÄ± kalkÄ±ÅŸ ve varÄ±ÅŸ yerleriyle beraber filterelenerek gettickets'a atanÄ±r
            startdate=gtdate - timedelta(days=30) 
            gettickets = tickets.query.filter(tickets.tdate <= enddate).filter(tickets.tdate >= startdate).filter_by(tfrom=gtfrom, twhere=gtwhere).order_by(desc(tickets.taseats)).all()
            return render_template("order.html", cities=getcities,currentdate=currentdate,tickets=gettickets,igtfrom=gtfrom,igtwhere=gtwhere,igtdate=gtdate,igtedate=gtedate)
            #gelen sonuÃ§lar order.html sayfasÄ±na gÃ¶nderilir
    if request.method == 'POST' and request.form['action'] == 'SÄ±fÄ±rla': 
        #SÄ±fÄ±rla butonuna basÄ±lmasÄ± durumunda filteleri kaldÄ±rarak getticketsi baÅŸtan sayfaya yÃ¶nlendirir
        gettickets = tickets.query.order_by(desc(tickets.taseats)).all()
        return render_template("order.html", cities=getcities,currentdate=currentdate,tickets=gettickets)

    gettickets = tickets.query.order_by(desc(tickets.taseats)).all()
    return render_template("order.html", cities=getcities,currentdate=currentdate,tickets=gettickets)




@application.route("/mngcity",methods=["POST","GET"])
def mngcity():
    if "admin" in session:
        
        if request.method =="POST":
            cname= request.form["cname"]
            exist = cities.query.filter_by(cname=cname).first()
            if exist:
                return "zaten var"
            else:
                db.session.add(cities(cname))
                db.session.commit()
        vcities = cities.query.order_by(cities.cid).all()
        return render_template("managecity.html",vcities=vcities)
    else:
        flash("Admin sayfasÄ±nÄ± gÃ¶rÃ¼ntÃ¼leme izniniz yok!", "info")
        return redirect(url_for("user"))

@application.route("/mngcity-delete/<int:id>")
def mngcitydel(id):
    if "admin" in session:
        exist = cities.query.filter_by(cid=id).first()
        if exist:
            db.session.delete(exist)
            db.session.commit()
            flash("City deleted successfully!", "info")
            return redirect(url_for("mngcity"))

    else:
        flash("Admin sayfasÄ±nÄ± gÃ¶rÃ¼ntÃ¼leme izniniz yok!", "info")
        return redirect(url_for("user"))    


@application.route("/reservation", methods=["POST","GET"])
def reserve():
    if "email" in session:
        email = session["email"]
        currentuser = users.query.filter_by(email=email).first() #session'u aktif olan kullanÄ±cÄ±yÄ± bul idsini aktar
        ownerid = currentuser.uid
    
        reservations = reservation.query.filter_by(ruid=ownerid,rstatus=1).all() #kullanÄ±cÄ±nÄ±n statÃ¼sÃ¼ 1 olan (satÄ±n alÄ±nmÄ±ÅŸ) rezervasyonlarÄ±nÄ± deÄŸiÅŸkene aktar

        if reservations: # rezervasyonlar var ise
            Name=currentuser.name + " " + currentuser.sname # kullanÄ±cÄ± ismini al
            flights= tickets.query.order_by(tickets.tid).all() #uÃ§uÅŸlarÄ± veritabanÄ±ndan al
            return render_template("reservation.html", Reservation=reservations,Name=Name,flights=flights) # bilgileri sayfaya gÃ¶nder
        else:
            flash("Rezervasyon BulunamadÄ±.", "info")
            return redirect(url_for("order"))    

    else :
        return redirect(url_for("user"))

@application.route("/ticket", methods=["POST","GET"])
def ticket():
    if "admin" in session:
        gettickets = tickets.query.order_by(tickets.tid).all()
        getcities = cities.query.order_by(cities.cid).all()
        currentdate = datetime.now(turkey).date()
        if request.method == "POST":
            if request.form['action'] == 'AddFlight':
                return redirect(url_for("addticket"))    
            if request.form['action'] == 'ViewFlights':
                return redirect(url_for("editticket"))       
        return render_template("ticket.html", tickets=gettickets, cities=getcities, currentdate=currentdate)
    else :
        return redirect(url_for("user"))
@application.route("/addticket", methods=["POST","GET"])
def addticket():
    if "admin" in session:
        if request.method == "POST":
            gtfrom, gtwhere,gttime,gtetime,gtprice,gtseats,gtaseats= (request.form[s] for s in ('gtfrom', 'gtwhere','gttime','gtetime','gtprice','gtseats','gtaseats'))
            gtdate = datetime.strptime(request.form["gtdate"], '%Y-%m-%d').date()
            #formdan verileri Ã§eker
            if gtdate < datetime.now(turkey).date():
                flash("GeÃ§miÅŸ tarihe uÃ§uÅŸ ekleyemezsiniz!")
            elif gtseats<gtaseats:
                flash("BoÅŸ koltuklar Koltuklardan fazla olamaz!")
            else:
                addticket = tickets(gtfrom,gtwhere,gtdate,gttime,gtetime,gtprice,gtseats,gtaseats)
                db.session.add(addticket) #verileri veritabanÄ±na ekler
                db.session.commit() #veritabanÄ±nÄ± gÃ¼nceller
                flash("UÃ§uÅŸ BaÅŸarÄ±yla Eklendi!")

        getcities = cities.query.order_by(cities.cid).all()
        currentdate = datetime.now(turkey).date()
        return render_template("addflight.html", cities=getcities, currentdate=currentdate)
    else :
        return redirect(url_for("user"))
@application.route("/editticket", methods=["POST","GET"])
def editticket():
    if "admin" in session:
        gettickets = tickets.query.order_by(tickets.tid).all()
        getcities = cities.query.order_by(cities.cid).all()
        currentdate = datetime.now(turkey).date()
        if request.method == "POST":
            if request.form['action'] == 'filter':
                gtfrom, gtwhere = (request.form[s] for s in ('gtfrom', 'gtwhere'))
                gettickets = tickets.query.filter_by(tfrom=gtfrom, twhere=gtwhere).all() #formdaki gtfrom ve gtwhere deÄŸiÅŸkenine gÃ¶re uÃ§uÅŸlarÄ± filtrele
                return render_template("editflight.html", tickets=gettickets, cities=getcities, currentdate=currentdate,igtfrom=gtfrom,igtwhere= gtwhere)
            else:
                gettickets = tickets.query.order_by(tickets.tid).all()

        return render_template("editflight.html", tickets=gettickets, cities=getcities, currentdate=currentdate)
    else :
        return redirect(url_for("user"))

@application.route("/deleteticket/<int:fid>", methods=["POST","GET"])
def deleteticket(fid):
    if "admin" in session:
        ticket = tickets.query.filter_by(tid=fid).first()
        ures = reservation.query.filter_by(rflightid=fid).all()
        for u in ures:
            db.session.delete(u)
        db.session.delete(ticket)
        db.session.commit()
        flash("UÃ§uÅŸ BaÅŸarÄ±yla Ä°ptal Edildi!")
        return redirect(url_for("editticket"))

@application.route("/ticketeditor/<int:fid>", methods=["POST","GET"])
def ticketeditor(fid): #dÄ±ÅŸarÄ±dan fid adÄ±nda veri alÄ±r
    if "admin" in session:
        ticket = tickets.query.filter_by(tid=fid).first() # fid ile dÃ¼zenlencek uÃ§uÅŸu bulur
        if request.method == "POST": # butona basÄ±lÄ±rsa
            gtseats,gtaseats = (request.form[s] for s in('gtseats','gtaseats')) # formdaki verileri alÄ±r
            gtdate = datetime.strptime(request.form["gtdate"], '%Y-%m-%d').date() # formdaki tarihi alÄ±r ve dÃ¼zenler
            if gtdate < datetime.now(turkey).date(): 
                flash("GeÃ§miÅŸ tarihe uÃ§uÅŸ ekleyemezsiniz!")
            elif gtseats<gtaseats:
                flash("BoÅŸ koltuklar Koltuklardan fazla olamaz!")
            else:
                ticket.tfrom,ticket.twhere,ticket.ttime,ticket.tetime,ticket.tprice,ticket.tseats,ticket.taseats =  (request.form[s] for s in ('gtfrom', 'gtwhere','gttime','gtetime','gtprice','gtseats','gtaseats'))
                ticket.tdate = gtdate
                #formdaki verileri veritabanÄ±na aktarÄ±r
                db.session.commit() # veritabanÄ±ndaki deÄŸiÅŸiklikleri kaydeder
                flash("UÃ§uÅŸ BaÅŸarÄ±yla DÃ¼zenlendi!")
            return redirect(url_for("editticket"))
        getcities = cities.query.order_by(cities.cid).all() #formdaki liste iÃ§in ÅŸehirleri alÄ±r
        return render_template("ticketeditor.html", ticket=ticket, cities=getcities)
    else:
        flash("Admin sayfasÄ±nÄ± gÃ¶rÃ¼ntÃ¼leme izniniz yok!", "info")
        return redirect(url_for("user")) 


@application.route("/deletereserve/<int:rid>", methods=["POST","GET"])
def deletereserve(rid):
    if "email" in session:
        ownerid=users.query.filter_by(email=session["email"]).first().uid
        ures = reservation.query.filter_by(rid=rid).first()
        db.session.delete(ures)
        db.session.commit()
        session["basket"] = reservation.query.filter_by(ruid=ownerid,rstatus=0).count()
        flash("Rezervasyon Ä°ptal Edildi!")
        return redirect(url_for("reserve"))

@application.route("/editreserve/<int:rid>", methods=["POST","GET"])
def editreserve(rid):
    if "email" in session:
        ures = reservation.query.filter_by(rid=rid).first()
        flight = tickets.query.filter_by(tid=ures.rflightid).first()
        if request.method == "POST":
            if int(request.form["seatn"])>flight.taseats:
                flash("UÃ§akta yeteri kadar yer yok!")
            else:
                ures.rseats = int(request.form["seatn"])
                db.session.commit()
                flash("Sepetiniz DÃ¼zenlendi")
                return redirect(url_for("basket"))
        owner=users.query.filter_by(email=session["email"]).first()
        return render_template("editreserve.html",ticket=flight, res=ures,user=owner)
    else:
        flash("GiriÅŸ YapÄ±n!")
        return redirect(url_for("user"))


@application.route("/register", methods=["POST","GET"])
def register():
    if "email" in session: #email sessionundaysa kullanÄ±cÄ± giriÅŸ yapmÄ±ÅŸtÄ±r yÃ¶nlendir
        flash("You're already logged in!")
        return redirect(url_for("user"))
    else:
        if request.method == "POST": #deÄŸilse butona basÄ±ldÄ±ÄŸÄ±nda formdaki verileri deÄŸiÅŸkenlere aktar
            fname = request.form["fname"]
            sname = request.form["sname"]
            password = hash_password(request.form["password"]) #ÅŸifreyi hashleme iÅŸlemi iÃ§in gÃ¶nderip aktar
            email = request.form["email"]
            rank = 1 # kullanÄ±cÄ± seviyesini 1 (kullanÄ±cÄ±) yap 
            found_user = users.query.filter_by(email=email).first() #e-mail hesabÄ±nÄ± veritabanÄ±nda ara
            if found_user:
                flash("this e-mail adress is already used on our system!") # bulunduysa kayÄ±tlÄ± olarak uyar, giriÅŸ sayfasÄ±na yÃ¶nlendir
                return redirect(url_for("login"))
            else :
                usr = users(fname,email,password,sname,rank) # deÄŸiÅŸkenleri usr deÄŸiÅŸkenine ata
                usr.bonus = 0
                db.session.add(usr) # usr deÄŸiÅŸkenini veritabanÄ±na ekle
                db.session.commit() # veri tabanÄ±nÄ± gÃ¼ncelle
                flash("You have been registered succesfully!")
                return redirect(url_for("login"))
        return render_template("register.html")



@application.route("/login", methods=["POST","GET"])
def login():
    if "email" in session:
        flash("You have already been logged in!")
        return redirect(url_for("user"))
    else:
        if request.method == "POST":
            session.permanent = True #sessionu kalÄ±cÄ± hale getir
            mail = request.form["email"]
            passwd = request.form["password"]
            found_user = users.query.filter_by(email=mail).first()

            if found_user:
                if verify_password(found_user.upwd, passwd): # hash kullanarak ÅŸifreyi kontrol et
                    session["email"] = found_user.email
                    if found_user.rank == 2: # seviye 2 ise admin sessionu oluÅŸtur
                        session["admin"] = mail
                    flash("You have been logged in successfully!", "info")
                    return redirect(url_for("user"))
                else:
                    flash("Your Password is incorrect!", "info")
            else:
                flash("E-mail adress is not registered in our system!", "info")
    return render_template("login.html")

@application.route("/user", methods=["POST","GET"])
def user():
    email = None
    if "email" in session: #giriÅŸ yapÄ±ldÄ±ysa
        email=session["email"]
        found_user = users.query.filter_by(email=email).first() #email'i sessiondan alÄ±p kullanÄ±cÄ±yÄ± bul
        fname=found_user.name # deÄŸiÅŸkenlere kullanÄ±cÄ± bilgilerini aktar
        sname=found_user.sname
        password="********"
        bonus=found_user.bonus

        if request.method == "POST": # butona tÄ±klanÄ±rsa formdaki verileri deÄŸiÅŸkenlere aktar
            fname=request.form["fname"]
            sname=request.form["sname"]
            email=request.form["email"]
            found_user.name = fname
            found_user.sname = sname
            found_user.email = email
            if request.form["paswd"] != "********": #ÅŸifre deÄŸiÅŸtirilmiÅŸse ÅŸifreyi hashleyerek deÄŸiÅŸkene ata
                found_user.upwd = hash_password(request.form["paswd"])
            session["email"] = email
            db.session.commit() # veritabanÄ±nÄ± gÃ¼ncelle
            flash("Successfully updated", "info")

        return render_template("user.html", fname=fname,sname=sname,email=email,password=password,bonus=bonus)
    else:
        flash("You are not logged in!", "info")
        return redirect(url_for("login"))

@application.route("/logout")
def logout():
    if "email" in session:
        session.pop("basket",None)
        user= users.query.filter_by(email=session["email"]).first()
        session.pop("email",None)
        baskets = reservation.query.filter_by(ruid=user.uid,rstatus=0).all()
        for basket in baskets:
            db.session.delete(basket)
        db.session.commit()
        if "admin" in session:
            session.pop("admin",None)
        flash("You have been logged out successfully!")
        return redirect(url_for("login"))
    else:
        flash("You are not logged in!", "info")
        return redirect(url_for("login"))

@application.route('/edit/<int:id>')
def edit(id):
    if "admin" in session:
        edituser = users.query.filter_by(uid=id).first()
        if edituser:
            db.session.delete(edituser)
            db.session.commit()
            flash("User deleted successfully!", "info")
            return redirect(url_for("admin"))
        else:
            flash("kullanÄ±cÄ± bulunamaadÄ±", "info")
            return redirect(url_for("admin"))
    else:
        flash("Bu sayfayÄ± gÃ¶rÃ¼ntÃ¼leme izniniz yok!", "info")
        return redirect(url_for("user"))
   
@application.route("/edituser/<int:id>", methods=["POST","GET"])
def edituser(id):
    if "admin" in session:
            edituser = users.query.filter_by(uid=id).first()
            
            if request.method == "POST":
                edituser.rank = request.form['rank']
                edituser.name = request.form['fname']
                edituser.sname = request.form['sname']
                edituser.email = request.form['email']
                if request.form['password'] != "********":
                    edituser.upwd = hash_password(request.form['password'])
                db.session.commit()
            if edituser:
                ename = edituser.name
                esname = edituser.sname
                eemail = edituser.email
                eupwd = "********"
                erank = edituser.rank
                euid = edituser.uid
                return render_template("edituser.html", euid=euid, ename=ename,esname=esname,eemail=eemail,eupwd=eupwd,erank=erank)
            else: 
                flash("Wrong User ID!", "info")
                return redirect(url_for("admin"))
    else:
        flash("Bu sayfayÄ± gÃ¶rÃ¼ntÃ¼leme izniniz yok!", "info")
        return redirect(url_for("user"))



  
    
if __name__ == "__main__":
    db.create_all()   
    application.run(debug=True)
