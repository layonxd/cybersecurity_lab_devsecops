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

    assert response.status_code == 200
    assert api.find_grade(1001, "SRS")["grade"] == 18