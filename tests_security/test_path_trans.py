
from urllib import response

import baseline_secure_coding_api as api

#Authenticated users may download teaching materials within the materials
#directory. Requests must not read files outside that directory.
#Tests if requires auth 
#Tests if path traversal is possible


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

def test_FAIL_path_tranversal_wo_auth(client):
    #login(client, "prof_srs", "profpw")
    response = client.get("/files", query_string={"path": "srs-summary.txt"})
    print(response.get_data(as_text=True))
    assert response.status_code != 200


def test_FAIL_path_tranversal_malicious(client):
    login(client, "prof_srs", "profpw")
    response = client.get("/files", query_string={"path": "../baseline_secure_coding_api.py"})

    assert response.status_code != 200
    print(response.get_data(as_text=True))
    assert response.get_data(as_text=True) != ""
#tem q printar mais cenas tipo src code e dar update ao validation

    