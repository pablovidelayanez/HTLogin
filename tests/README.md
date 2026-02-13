# HTLogin Test Suite

Bu klasör HTLogin projesi için unit testleri içerir.

## Kurulum

Testleri çalıştırmak için önce gerekli bağımlılıkları kurun:

```bash
pip install -r requirements.txt
```

## Testleri Çalıştırma

Tüm testleri çalıştırmak için:

```bash
pytest
```

veya

```bash
python -m pytest
```

Belirli bir test dosyasını çalıştırmak için:

```bash
pytest tests/test_config.py
```

Belirli bir test fonksiyonunu çalıştırmak için:

```bash
pytest tests/test_config.py::TestConfig::test_config_default_values
```

## Test Coverage

Coverage raporu ile testleri çalıştırmak için:

```bash
pytest --cov=. --cov-report=html
```

Bu komut HTML coverage raporu oluşturur (`htmlcov/index.html`).

## Test Dosyaları

- `test_config.py`: Config sınıfı ve yapılandırma yönetimi testleri
- `test_form_parser.py`: FormParser sınıfı ve HTML form parsing testleri (CAPTCHA detection dahil)
- `test_detection.py`: LoginSuccessDetector ve güven skoru hesaplama testleri
- `test_credentials.py`: CredentialProvider ve credential yönetimi testleri
- `test_api_discovery.py`: APIDiscovery sınıfı ve API endpoint discovery testleri
- `test_api_tester.py`: APITester sınıfı ve JSON API/GraphQL login testleri

## Test Yapısı

Testler pytest framework'ü kullanılarak yazılmıştır. Her test dosyası ilgili modül için test sınıfları içerir.

Testler şu kategorilere ayrılır:
- **Unit Tests**: Tekil fonksiyon ve sınıf testleri
- **Integration Tests**: Modüller arası etkileşim testleri
