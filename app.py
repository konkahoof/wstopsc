from flask import Flask, request, redirect, url_for, make_response,render_template
import functools
import hashlib
import json
from bs4 import BeautifulSoup
import requests

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

@app.route('/res', methods=['GET'])
def scraper():
    #dia musavat yenicag  cf_clearance=8SFoZzwGXsViOZzXANRFQnIb_N4h328Id4TQGYUbuxs-1680443551-0-160;
    headersf = {
        "cookie":"cf_clearance=zHQDGp79IGPynjKH6mKWCwkc9hCkYyLNKkaFLkuw.us-1682327995-0-150;YMQ2019=05e9b270802b5b41869fc4e3e26fb910;lang=az;current_lang=az",
        "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36"}
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
                        haber_linki = "url-not-found"
                        if item['site'] == "https://interpress.az/" or item['site'] == "https://apa.az/" or item['site'] == "https://1news.az/" or item['site'] == "https://bizim.media/" or item['site'] == "https://moderator.az/" or item['site'] == "https://ednews.net/" or item['site'] == "https://pressklub.az/" or item['site'] == "https://haqqin.az/":
                            haber_linki = haber_div['href']
                            
                    if haber_linki.split("/")[0][0:4] != "http":
                        haber_linki= item['site']+haber_linki
                    news["news_link"]  = haber_linki
                    if item['site'] == "https://azpolitika.info/" or item['site'] == "https://oxu.az/" or item['site'] == "https://azertag.az/" or item['site'] == "https://musavat.com/" or item['site'] == "https://cebheinfo.az/" or item['site'] == "https://ednews.net/" or item['site'] == "https://baymedia.az/":
                        news["news_link"]  = haber_linki.replace("//","/")
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
