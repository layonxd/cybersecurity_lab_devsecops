
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
    #login(client, "prof_srs", "profpw")
    response = client.get("/files", query_string={"path": "srs-summary.txt"})

    assert response.status_code == 200
    assert response.get_data(as_text=True) == "SRS Summary: This is a summary of the SRS course."

def test_path_tranversal_malicious(client):
    #login(client, "prof_srs", "profpw")
    response = client.get("/files", query_string={"path": "../baseline_secure_coding_api.py"})

    assert response.status_code == 200
    print(response.get_data(as_text=True))
    assert response.get_data(as_text=True) != ""   

    