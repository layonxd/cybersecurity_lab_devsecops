
from urllib import response

import baseline_secure_coding_api as api

def login(client, username, password):
    response = client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert response.get_json()["user"] == username
    
def test_path_tranversal(client):
    login(client, "prof_srs", "profpw")
    response = client.get("/files", query_string={"path": "srs-summary.txt"})
    print(response.get_data(as_text=True))
    assert response.status_code == 200
    assert response.get_data(as_text=True) == "Secure Requirements Engineering summary"

def test_path_tranversal_wo_auth(client):
    #login(client, "prof_srs", "profpw")
    response = client.get("/files", query_string={"path": "srs-summary.txt"})
    print(response.get_data(as_text=True))
    assert response.status_code == 200
    assert response.get_data(as_text=True) == "Secure Requirements Engineering summary"


def test_path_tranversal_malicious(client):
    login(client, "prof_srs", "profpw")
    response = client.get("/files", query_string={"path": "../baseline_secure_coding_api.py"})

    assert response.status_code == 200
    print(response.get_data(as_text=True))
    assert response.get_data(as_text=True) != ""   

    