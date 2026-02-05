# lidio-puan-point-checker
fully reverse-engineered point checker for lidio, can be developed
loyalty point checker tools for turkish e-commerce sites

## cgrtchibo

tchibo.com.tr loyalty point checker. checks card points through their payment gateway.

- proxy support (rotating proxies work best)
- parallel card checking
- session management
- card generator from bin patterns

run it:
```
cd cgrtchibo/cgrama
pip install -r ../requirements.txt
python app.py
```
then open http://localhost:5000

## cgrna

turna.com loyalty point checker. uses their mobile api with session rotation.

- auto session creation
- proxy support
- parallel checking
- card generator

run it:
```
cd cgrna
pip install -r requirements.txt
python app.py
```
then open http://localhost:5000

## notes

- you need proxies for both, rotating proxies recommended
- proxy format: `host:port:user:pass`
- card format: `cardno|mm|yyyy|cvv`
- sessions are saved locally, cleared on restart

---

## turkce

turkiye e-ticaret sitelerinde puan sorgulama araci

### cgrtchibo

tchibo.com.tr puan sorgulama. lidio odeme gecidi uzerinden kart puanlarini kontrol eder.

- proxy destegi (rotating proxy oneriyorum)
- paralel kart kontrolu
- oturum yonetimi
- bin'den kart uretici

calistirmak icin:
```
cd cgrtchibo/cgrama
pip install -r ../requirements.txt
python app.py
```
sonra http://localhost:5000 ac

### cgrna

turna.com puan sorgulama. mobil api kullanir, oturum rotasyonu var.

- otomatik oturum olusturma
- proxy destegi
- paralel kontrol
- kart uretici

calistirmak icin:
```
cd cgrna
pip install -r requirements.txt
python app.py
```
sonra http://localhost:5000 ac

### notlar

- ikisi icin de proxy lazim, rotating proxy onerilir
- proxy formati: `host:port:user:pass`
- kart formati: `kartno|ay|yil|cvv`
- oturumlar lokalde tutuluyor, restart'ta sifirlaniyor

---

## by skzyzskz

### disclaimer

this is for educational purposes only. using this on cards you dont own is illegal. i dont take any responsibility for what you do with this. use at your own risk.

### sorumluluk reddi

bu sadece egitim amaclidir. size ait olmayan kartlarda kullanmak yasadisidir. bununla ne yaptiginizdan sorumlu degilim. risk size ait.
