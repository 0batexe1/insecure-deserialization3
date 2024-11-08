import requests
import random
import time
import json
import itertools
from sklearn.ensemble import IsolationForest  # type: ignore
from sklearn.model_selection import train_test_split, cross_val_score  # type: ignore
from sklearn.preprocessing import StandardScaler  # type: ignore
from sklearn.metrics import accuracy_score  # type: ignore

# ----------------- Gelişmiş Payload Kombinasyonları -----------------
def generate_payload_combinations():
    payloads = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', "' OR 1=1 --"]
    combinations = itertools.permutations(payloads, 2)
    return combinations

# ----------------- Makine Öğrenmesi ile Anomali Algılama -----------------
def anomaly_detection(data):
    # Veriyi standartlaştırma
    scaler = StandardScaler()
    scaled_data = scaler.fit_transform(data)
    
    # Anomali algılama için Isolation Forest
    model = IsolationForest(n_estimators=100, contamination=0.1)
    model.fit(scaled_data)
    predictions = model.predict(scaled_data)
    
    # Anomali tespiti
    anomalies = [i for i, prediction in enumerate(predictions) if prediction == -1]
    return anomalies

# ----------------- Makine Öğrenmesi Modeli Eğitimi -----------------
def train_ml_model(data, labels):
    # Veriyi eğitim ve test olarak bölelim
    X_train, X_test, y_train, y_test = train_test_split(data, labels, test_size=0.3, random_state=42)
    
    # Model oluşturma
    model = IsolationForest(n_estimators=100, contamination=0.1)
    model.fit(X_train)
    
    # Test seti üzerinde doğruluk hesaplama
    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)
    
    print(f"Model doğruluğu: {accuracy * 100:.2f}%")
    return model

# ----------------- Fuzzing ve Parametre Manipülasyonu -----------------
def fuzz_url(url, param_name, payloads):
    for payload in payloads:
        fuzzed_url = f"{url}?{param_name}={payload}"
        response = requests.get(fuzzed_url)
        if response.status_code == 200:
            print(f"Başarılı Fuzzed URL: {fuzzed_url} - Status: {response.status_code}")

# ----------------- Zamansal Rastgelelik -----------------
def add_random_delay():
    delay = random.uniform(1, 5)  # 1 ile 5 saniye arasında rastgele bir gecikme
    time.sleep(delay)
    print(f"Geçikme ekleniyor: {delay} saniye")

# ----------------- Yanıtın Gerçek Zamanlı Kategorik Analizi -----------------
def categorize_response(response):
    if "error" in response.text:
        return "Hata"
    elif "success" in response.text:
        return "Başarı"
    else:
        return "Bilinmeyen"

# ----------------- Çok Katmanlı Doğrulama -----------------
def multi_stage_verification(url):
    # 1. Payload gönder
    payload = "malicious_payload"
    response_1 = requests.get(f"{url}?payload={payload}")
    
    if response_1.status_code == 200:
        print("İlk doğrulama başarılı!")
        # 2. İkinci aşama doğrulama
        response_2 = requests.get(url)
        if response_2.status_code == 200:
            print("İkinci aşama doğrulama başarılı!")
        else:
            print("İkinci aşama başarısız!")
    else:
        print("İlk aşama başarısız!")

# ----------------- Ağ Trafiği ve Paket Kaydı -----------------
def log_network_traffic(url):
    # Ağ trafiği kaydediyoruz
    print(f"Ağ trafiği kaydediliyor: {url}")
    response = requests.get(url)
    print(f"Paket kaydı yapıldı: {response.status_code}")

# ----------------- Esnek API Gönderim Yapılandırması -----------------
def send_payload_via_api(api_url, payload):
    response = requests.post(api_url, data={"payload": payload})
    print(f"API'ye gönderilen payload: {payload} - Yanıt: {response.status_code}")

# ----------------- Dinamik API'den Payload Alma -----------------
def fetch_payload_from_api(api_url):
    response = requests.get(api_url)
    if response.status_code == 200:
        return response.json()['payloads']
    else:
        return []

# ----------------- API'ye Rapor Gönderme -----------------
def send_report_to_api(api_url, report_data):
    headers = {'Content-Type': 'application/json'}
    response = requests.post(api_url, data=json.dumps(report_data), headers=headers)
    print(f"API'ye rapor gönderildi - Yanıt: {response.status_code}")
    return response.json()

# ----------------- Ana Program Akışı -----------------
def main():
    # Kullanıcıdan URL al
    url = input("Hedef URL girin (örneğin: http://example.com): ")
    api_url = input("API URL'sini girin (örneğin: http://api.example.com/payload): ")
    api_report_url = input("API rapor URL'sini girin (örneğin: http://api.example.com/report): ")

    # 1. Payload kombinasyonlarını oluştur
    combinations = generate_payload_combinations()
    print("Payload Kombinasyonları:")
    for combination in combinations:
        print(combination)
    
    # 2. Fuzzing ve parametre manipülasyonu
    fuzz_url(url, "param1", ["payload1", "payload2", "payload3"])
    
    # 3. Zamansal rastgelelik ekle
    add_random_delay()
    
    # 4. Yanıt kategorisi tespiti
    response = requests.get(url)
    category = categorize_response(response)
    print(f"Yanıt Kategorisi: {category}")
    
    # 5. Başarılı sonuçları anlık olarak yazdır
    data = [
        {"payload": "payload1", "status": "success"},
        {"payload": "payload2", "status": "failure"}
    ]
    for entry in data:
        if entry['status'] == 'success':
            print(f"Başarılı Test: Payload: {entry['payload']} - Durum: {entry['status']}")
    
    # 6. Çok Katmanlı doğrulama
    multi_stage_verification(url)
    
    # 7. Ağ trafiğini kaydet
    log_network_traffic(url)
    
    # 8. API üzerinden payload gönder
    send_payload_via_api(api_url, "malicious_payload")
    
    # 9. Makine öğrenmesi ile anomali algılama
    sample_data = [[1, 2], [1, 3], [10, 10], [2, 3], [3, 4]]  # Örnek veri
    anomalies = anomaly_detection(sample_data)
    print(f"Tespit edilen anomali indeksleri: {anomalies}")
    
    # 10. API'den dinamik payload al
    fetched_payloads = fetch_payload_from_api(api_url)
    print(f"API'den alınan payloadlar: {fetched_payloads}")
    
    # 11. Makine öğrenmesi modelini eğit ve doğruluğu test et
    data_for_ml = [[1, 2], [2, 3], [10, 11], [3, 4], [5, 6]]  # Daha büyük verilerle eğitilebilir
    labels_for_ml = [1, 1, -1, 1, 1]  # Etiketler: -1 anomali, 1 normal
    model = train_ml_model(data_for_ml, labels_for_ml)
    
    # 12. API'ye rapor gönder
    report_data = {"status": "success", "message": "Rapor başarıyla alındı"}
    send_report_to_api(api_report_url, report_data)

if __name__ == "__main__":
    main()
