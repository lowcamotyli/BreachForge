from __future__ import annotations

from execution_plane.crawler.code_extractors import extract_routes
from execution_plane.crawler.code_extractors.express_extractor import extract_express_routes
from execution_plane.crawler.code_extractors.fastapi_extractor import extract_fastapi_routes
from execution_plane.crawler.code_extractors.rails_extractor import extract_rails_routes
from execution_plane.crawler.code_extractors.spring_extractor import extract_spring_routes


def test_extracts_fastapi_routes() -> None:
    code = """
    @app.get("/users")
    async def list_users(): ...

    @router.post('/users')
    async def create_user(): ...

    @router.patch("users/{id}")
    async def update_user(): ...
    """

    assert extract_fastapi_routes(code) == [
        {"method": "GET", "path": "/users"},
        {"method": "POST", "path": "/users"},
        {"method": "PATCH", "path": "/users/{id}"},
    ]


def test_extracts_express_routes() -> None:
    code = """
    app.get("/users", listUsers);
    router.post('/users', createUser);
    router.all("status", healthCheck);
    """

    assert extract_express_routes(code) == [
        {"method": "GET", "path": "/users"},
        {"method": "POST", "path": "/users"},
        {"method": "ALL", "path": "/status"},
    ]


def test_extracts_rails_routes() -> None:
    code = """
      get "/login"
      post 'sessions'
      resources :users
    """

    assert extract_rails_routes(code) == [
        {"method": "GET", "path": "/login"},
        {"method": "POST", "path": "/sessions"},
        {"method": "GET", "path": "/users"},
        {"method": "POST", "path": "/users"},
        {"method": "GET", "path": "/users/{id}"},
        {"method": "PUT", "path": "/users/{id}"},
        {"method": "PATCH", "path": "/users/{id}"},
        {"method": "DELETE", "path": "/users/{id}"},
    ]


def test_extracts_spring_routes() -> None:
    code = """
    @GetMapping("/users")
    public List<User> listUsers() {}

    @PostMapping("users")
    public User createUser() {}

    @RequestMapping(value="/users/{id}", method=RequestMethod.DELETE)
    public void deleteUser() {}
    """

    assert extract_spring_routes(code) == [
        {"method": "GET", "path": "/users"},
        {"method": "POST", "path": "/users"},
        {"method": "DELETE", "path": "/users/{id}"},
    ]


def test_extract_routes_dispatcher() -> None:
    assert extract_routes('@app.get("/users")', "fastapi") == [{"method": "GET", "path": "/users"}]
    assert extract_routes('app.post("/users", handler);', "express") == [{"method": "POST", "path": "/users"}]
    assert extract_routes('patch "/users/:id"', "rails") == [{"method": "PATCH", "path": "/users/:id"}]
    assert extract_routes('@PutMapping("/users/{id}")', "spring") == [{"method": "PUT", "path": "/users/{id}"}]


def test_extract_routes_unknown_framework_returns_empty_list() -> None:
    assert extract_routes('@app.get("/users")', "django") == []
