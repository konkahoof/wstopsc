from flask import Flask, request, redirect, url_for, make_response,render_template
from urllib.parse import urlparse
from bs4 import BeautifulSoup, Comment
from bs4.element import Tag
import functools
import hashlib
import json
import requests
import re

app = Flask(__name__)


jsonfile = 'static/data.json'
app.secret_key = 'YWNpbHN1c2FtYWNpbCE='  # Güvenliğiniz için değiştirin
correct_key = '2b3e1e819aa20c6e7133d36a055732487e0f95dcebc6034e0866a6cb168b90f9'#acilsusamacil!
def sifrele(data, key=app.secret_key):
    combined_data = data + key
    md5_hash = hashlib.md5(combined_data.encode()).hexdigest()    
    sha256_hash = hashlib.sha256(md5_hash.encode()).hexdigest()    
    return sha256_hash
def check_key(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if request.cookies.get('auth_key') == correct_key:
            return f(*args, **kwargs)
        return redirect(url_for('login'))
    return decorated_function

@app.route('/')
@check_key
def home():
    with open(jsonfile) as file:
        data = json.loads(file.read())
    sites = []
    for site in data:    
        sites.append(site["site"])
    return render_template('home.html', sites=sites)

#dia musavat yenicag  cf_clearance=8SFoZzwGXsViOZzXANRFQnIb_N4h328Id4TQGYUbuxs-1680443551-0-160;
headersf = {
    "cookie":"cf_clearance=zHQDGp79IGPynjKH6mKWCwkc9hCkYyLNKkaFLkuw.us-1682327995-0-150;YMQ2019=05e9b270802b5b41869fc4e3e26fb910;lang=az;current_lang=az",
    "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36"
    }
@app.route('/res', methods=['GET'])
def scraper():
    if 'url' in request.args and request.args.get('url') is not None:
        url = request.args.get('url')
        print(f"Requested URL: {url}")
        with open(jsonfile) as file:
            data = json.loads(file.read())
        for item in data:
            if item['site'] == url :
                ull = f"{item['urls']}"
                r = requests.get(item['site']+ull,headers=headersf)
                soup = BeautifulSoup(r.content, 'html.parser')
                haberler_div = soup.select_one(item['mainblok'])
                lim=19
                newss=[]
                for i, haber_div in enumerate(haberler_div.select(item['item'])):
                    news={}
                    try:
                        haber_linki = haber_div.find('a')['href']
                        if url == "https://caliber.az/":
                            haber_linki = haber_div.find_all('a')[1]['href']
                    except:  
                        try:
                            haber_linki = haber_div['href'] 
                        except:
                            continue
                    if haber_linki.split("/")[0][0:4] != "http":
                        haber_linki=haber_linki[1:] if haber_linki.startswith('/') else haber_linki
                        haber_linki= item['site']+haber_linki
                    news["news_link"]  = haber_linki                        

                    try:
                        haber_baslik=haber_div.select_one(item['title']).text.strip()
                    except:
                        haber_baslik=haber_div.text.strip()
                    news["news_title"] = haber_baslik
                    if haber_linki.split("/")[3] != "url-not-found":
                        newss.append(news)
                    if i == lim:
                        break
    return json.dumps(newss)

def dosyaya_yaz(dosya_adi, veri):
    with open(dosya_adi, 'w') as dosya:
        dosya.write(veri)
def simplify_url(url):
    parsed_url = urlparse(url)
    simplified_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
    return simplified_url.replace("www.","")
def souptanCumleTagiSil(soup,tag_sentence):
    # Belirtilen cümleyi içeren etiketleri kaldırmak
    for element in soup.find_all(text=lambda text: tag_sentence in text):
        parent = element.parent
        if parent:
            parent.extract()
def souptanCumleSil(soup,target_sentence):
    # Belirtilen cümleyi içeren etiketleri bulmak ve cümleyi kaldırmak
    for element in soup.find_all(text=lambda text: target_sentence in text):
        if target_sentence in element:
            new_text = element.replace(target_sentence, '')
            element.replace_with(new_text)
def clearscr(soup):
    # `style` ve `script` etiketlerini kaldır
    for tag in soup(["style", "script","meta","link"]):
        tag.decompose()
    # Tüm etiketlerdeki `style` özniteliklerini kaldır
    for tag in soup.find_all(True):
        if tag.has_attr("style"):
            del tag["style"]
    if soup.find_all('iframe') :
        for iframe in soup.find_all('iframe'):
            if '/extra/' in iframe.get('src', ''):
                iframe.decompose()
    if soup.find_all('p') :#sia.az
        for p in soup.find_all('p'):
            if 'Bütün xəbərlər Facebook səhifəmizdə' in p.text:
                p.decompose()
 
    if soup.find_all('a') :
        for iframe in soup.find_all('a'):
            if '//www.facebook.com/profile.php?id=' in iframe.get('href', ''):
                iframe.decompose()
    if soup.find_all('a') :
        for iframe in soup.find_all('a'):
            if '//wa.me' in iframe.get('href', ''):
                iframe.decompose()
    if soup.find_all('a') :
        for iframe in soup.find_all('a'):
            if '//api.whatsapp' in iframe.get('href', ''):
                iframe.decompose()
    if soup.find_all('a') :
        for iframe in soup.find_all('a'):
            if '//t.me' in iframe.get('href', ''):
                iframe.decompose()        
    for element in soup(text=lambda text: isinstance(text, Comment)):
        element.extract()  
    souptanCumleTagiSil(soup,"Şikayətiniz varsa Whatsapp:")#big.az
    souptanCumleTagiSil(soup,"Bütün xəbərlər Facebook səhifəmizdə")#sia.az
    souptanCumleTagiSil(soup,"Teqlər:")#ordu.az
    souptanCumleTagiSil(soup,"© Materiallardan istifadə edərkən hiperlinklə istinad olunmalıdır")#ordu.az
    souptanCumleTagiSil(soup,"Тэги:")#armiya.az
    souptanCumleSil(soup,"Следите за актуальными военными новостями в нашем Telegram-канале")
    souptanCumleSil(soup,"Следите за актуальными военными новостями в нашем")
    """      
    for p in soup.find_all('p'):
        if not p.get_text(strip=True):
            p.extract()
    for div in soup.find_all('div'):
        if not div.get_text(strip=True):
            div.extract()
    """
    return soup

def temizle_html(data,blok):
    try:
        for blk in blok:
            for tag in data.select(blk):
                if isinstance(tag, Tag):
                    tag.decompose()
    except:
        blok
    return data


@app.route('/haber', methods=['GET'])
def haberscraper():
    if 'url' in request.args and request.args.get('url') is not None:
        post = request.args.get('url')
    print(f"Requested URL: {post}")
    print(simplify_url(post) )
    with open(jsonfile) as file:
        data = json.loads(file.read())
    for item in data:
        if item['site'] == simplify_url(post) :
            news={}
            r = requests.get(post,headers=headersf)
            soup = BeautifulSoup(r.content, 'html.parser', from_encoding='utf-8')
            if item['site'] != "https://olke.az/" and item['site'] != "https://xural.com/" :
                print(item['site'])
                soup = clearscr(soup)
            try:
                soup = temizle_html(soup,item['adblk'])
            except:
                soup
            try:
                haber = soup.select_one(item['postblok'])
                title=haber.select_one(item['posttitle'])
                news["title"]=title.text

                title = haber.select_one(item['posttitle'])

                if title:
                    if title.text in haber.text:
                        title.decompose()

                news["text"]=str(haber.select_one(item['posttext'])).replace("\n","")
            except:
                news["title"]="Halhazırda bu kontent mövcud deyil"
                news["text"]=str("bu kontent mövcud deyil <a href='"+post+"' class='btncon' target='_blank'>Sayta Keçid</a> edib oxuyabilersiniz")
    if  simplify_url(post) == "https://medicina.az/":
        news={}
        news["title"]="medicina.az linki"
        news["text"]=str("bu kontent mövcud deyil <a href='"+post+"' class='btncon' target='_blank'>Sayta Keçid</a> edib oxuyabilersiniz")

    print(news)
    return json.dumps(news, indent=4, ensure_ascii=False)





@app.errorhandler(404)
def error(e):
    return render_template("404.html")

@app.route('/login', methods=['GET', 'POST'])
def login():    
    cookie_name = 'auth_key'
    if cookie_name in request.cookies and request.cookies.get(cookie_name) == correct_key:
        return  redirect(url_for('home'))
    else:
        if request.method == 'POST':
            entered_key = sifrele(request.form['key'])
            if entered_key == correct_key:
                resp = make_response(redirect(url_for('home')))
                resp.set_cookie('auth_key', entered_key)
                return resp
            else:
                return "Yanlış anahtar, tekrar deneyin!"
        return render_template('login.html')

@app.route('/logout')
@check_key
def logout():
    resp = make_response(redirect(url_for('login')))
    resp.delete_cookie('auth_key')
    return resp

if __name__ == '__main__':
    app.run(debug=True)
