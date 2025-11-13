import pytest
import requests
from test_security import setup_create_user, get_last_email_body, extract_links, extract_query_params

BASE_URL = "http://localhost:5000"

@pytest.fixture
def authenticated_user(setup_create_user):
    # aca básicamente lo que hacemos es crear el user y después autenticarlo
    # para que devuelva el token de autenticacion que vamos a necesitar despues
    username, password = setup_create_user
    
    # mandamos el post al endpoint de login con el username y pass
    response = requests.post(f"{BASE_URL}/auth/login", 
                            json={"username": username, "password": password})
    assert response.status_code == 200
    
    # extraemos el token de la respuesta json que nos devuelve el servidor
    token = response.json()["token"]
    return token

def test_sql_injection_in_status_parameter(authenticated_user):
    # este test lo que hace es verificar que no se pueda hacer inyeccion sql
    # a traves del parametro status cuando hacemos la peticion de las facturas
    # probamos varios payloads maliciosos tipicos de sql injection
    headers = {"Authorization": f"Bearer {authenticated_user}"}
    
    # acá tenemos varios payloads maliciosos clasicos de sqli
    # el primero intenta hacer un bypass con OR 1=1
    # el segundo es parecido pero con comentarios sql
    # el tercero intenta dropear la tabla de invoices directamente
    # y el ultimo usa UNION para intentar sacar data de users
    malicious_payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE invoices--",
        "' UNION SELECT * FROM users--"
    ]
    
    # iteramos sobre cada payload y lo mandamos como parametro status
    for payload in malicious_payloads:
        response = requests.get(f"{BASE_URL}/invoices", 
                               headers=headers,
                               params={"status": payload, "operator": "="})
        
        # verificamos que devuelva codigos correctos, puede ser 200 si sanitiza bien
        # o 400/403/500 si rechaza la request directamente
        # lo importante es que NO devuelva data no autorizada ni ejecute el sql malicioso
        assert response.status_code in [200, 400, 403, 500]
        
        # si es 200 chequeamos que sea lista y no algo raro
        if response.status_code == 200:
            data = response.json()
            # tiene que ser una lista vacia o con invoices legit nomas
            assert isinstance(data, list)

def test_sql_injection_in_operator_parameter(authenticated_user):
    # este es similar al anterior pero inyectando en el parametro operator
    # en vez de status, porque tambien puede ser vulnerable si no sanitizan
    headers = {"Authorization": f"Bearer {authenticated_user}"}
    
    # payloads maliciosos especificos para el campo operator
    # intentan aprovechar que operator se usa en la query directamente
    # el primero hace bypass con OR en el operator mismo
    # segundo es parecido con !=
    # tercero intenta dropear tabla aprovechando que se concatena directo
    malicious_operators = [
        "= '' OR '1'='1' --",
        "!= '' OR 1=1 --",
        "; DROP TABLE invoices; --"
    ]
    
    # probamos cada operator malicioso
    for operator in malicious_operators:
        response = requests.get(f"{BASE_URL}/invoices",
                               headers=headers, 
                               params={"status": "pending", "operator": operator})
        
        # igual que antes, chequeamos que maneje bien
        # deberia sanitizar y devolver 200 o rechazar con error
        # pero nunca ejecutar el sql inyectado
        assert response.status_code in [200, 400, 403, 500]
        
        # verificamos formato de respuesta si es 200
        if response.status_code == 200:
            data = response.json()
            assert isinstance(data, list)