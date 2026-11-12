import baseline_secure_coding_api as api

def login(client, username, password):
    response = client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert response.get_json()["user"] == username
    
def test_real_student_can_view_grades(client):
    login(client, "alice", "alicepw")
    response = client.get(
        "/grades",
        json={"student_id": 1001, "course_id": "SRS"},
    )
    assert response.status_code == 200
    assert api.find_grade(1001, "SRS")["grade"] == 18


def test_fake_student_cannot_view_grades(client):
    login(client, "fake", "fake")
    response = client.get(
        "/grades",
        json={"student_id": 1001, "course_id": "SRS"},
    )
    assert response.status_code == 200
    assert api.find_grade(1001, "SRS")["grade"] == 18


def test_real_student_cannot_view_other_students_grades(client):
    login(client, "alice", "alicepw")
    response = client.get(
        "/grades",
        json={"student_id": 1002, "course_id": "SRS"},
    )
    assert response.status_code == 200
    assert api.find_grade(1002, "SRS")["grade"] == 18