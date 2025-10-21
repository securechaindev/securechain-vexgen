import pytest

from app.templates.file.tix_template import create_tix_template
from app.templates.file.tix_template import template as tix_template
from app.templates.file.vex_template import create_vex_template, template
from app.templates.statement.tix_statement_template import create_tix_statement_template
from app.templates.statement.tix_statement_template import template as tix_stmt_template
from app.templates.statement.vex_statement_template import create_vex_statement_template
from app.templates.statement.vex_statement_template import template as vex_stmt_template


class TestVEXTemplate:
    def test_vex_template_structure(self):
        tmpl = template()

        assert "@context" in tmpl
        assert "@id" in tmpl
        assert "author" in tmpl
        assert "role" in tmpl
        assert "timestamp" in tmpl
        assert "last_updated" in tmpl
        assert "version" in tmpl
        assert "tooling" in tmpl
        assert "statements" in tmpl

    def test_vex_template_values(self):
        tmpl = template()

        assert tmpl["@context"] == "https://openvex.dev/ns/v0.2.0"
        assert tmpl["@id"] == "https://github.com/securechaindev/securechain-vexgen"
        assert tmpl["version"] == 1
        assert tmpl["statements"] == []

    @pytest.mark.asyncio
    async def test_create_vex_template(self):
        tmpl1 = await create_vex_template()
        tmpl2 = await create_vex_template()

        assert tmpl1 == tmpl2

        tmpl1["author"] = "test"
        assert tmpl2["author"] == ""

    @pytest.mark.asyncio
    async def test_create_vex_template_is_mutable(self):
        tmpl = await create_vex_template()
        tmpl["statements"].append({"test": "statement"})

        original = template()
        assert len(original["statements"]) == 0


class TestTIXTemplate:
    def test_tix_template_structure(self):
        tmpl = tix_template()

        assert "@context" in tmpl
        assert "@id" in tmpl
        assert "author" in tmpl
        assert "role" in tmpl
        assert "timestamp" in tmpl
        assert "last_updated" in tmpl
        assert "version" in tmpl
        assert "tooling" in tmpl
        assert "statements" in tmpl

    def test_tix_template_values(self):
        tmpl = tix_template()

        assert "Thread-Intelligence-eXchange" in tmpl["@context"]
        assert tmpl["@id"] == "https://github.com/securechaindev/securechain-vexgen"
        assert tmpl["version"] == 1
        assert tmpl["statements"] == []
        assert "TIX" in tmpl["role"]

    @pytest.mark.asyncio
    async def test_create_tix_template(self):
        tmpl1 = await create_tix_template()
        tmpl2 = await create_tix_template()

        assert tmpl1 == tmpl2

        tmpl1["author"] = "test"
        assert tmpl2["author"] == ""

    @pytest.mark.asyncio
    async def test_create_tix_template_is_mutable(self):
        tmpl = await create_tix_template()
        tmpl["statements"].append({"test": "statement"})

        original = tix_template()
        assert len(original["statements"]) == 0


class TestVEXStatementTemplate:
    def test_vex_statement_template_structure(self):
        tmpl = vex_stmt_template()

        assert "vulnerability" in tmpl
        assert "timestamp" in tmpl
        assert "last_updated" in tmpl
        assert "products" in tmpl
        assert "status" in tmpl
        assert "supplier" in tmpl
        assert "justification" in tmpl

    def test_vex_statement_template_defaults(self):
        tmpl = vex_stmt_template()

        assert isinstance(tmpl["vulnerability"], dict)
        assert "@id" in tmpl["vulnerability"]
        assert tmpl["timestamp"] == ""
        assert tmpl["last_updated"] == ""
        assert isinstance(tmpl["products"], list)
        assert len(tmpl["products"]) == 1

    @pytest.mark.asyncio
    async def test_create_vex_statement_template(self):
        stmt1 = await create_vex_statement_template()
        stmt2 = await create_vex_statement_template()

        assert stmt1 == stmt2

        stmt1["vulnerability"]["@id"] = "CVE-2023-1234"
        assert stmt2["vulnerability"]["@id"] == ""

    @pytest.mark.asyncio
    async def test_create_vex_statement_template_is_mutable(self):
        stmt = await create_vex_statement_template()
        stmt["products"].append({"test": "product"})

        original = vex_stmt_template()
        assert len(original["products"]) == 1


class TestTIXStatementTemplate:
    def test_tix_statement_template_structure(self):
        tmpl = tix_stmt_template()

        assert "vulnerability" in tmpl
        assert "timestamp" in tmpl
        assert "last_updated" in tmpl
        assert "products" in tmpl
        assert "reachable_code" in tmpl
        assert "exploits" in tmpl

    def test_tix_statement_template_defaults(self):
        tmpl = tix_stmt_template()

        assert isinstance(tmpl["vulnerability"], dict)
        assert "@id" in tmpl["vulnerability"]
        assert tmpl["timestamp"] == ""
        assert tmpl["last_updated"] == ""
        assert isinstance(tmpl["products"], list)

    @pytest.mark.asyncio
    async def test_create_tix_statement_template(self):
        stmt1 = await create_tix_statement_template()
        stmt2 = await create_tix_statement_template()

        assert stmt1 == stmt2

        stmt1["vulnerability"]["@id"] = "CVE-2023-5678"
        assert stmt2["vulnerability"]["@id"] == ""

    @pytest.mark.asyncio
    async def test_create_tix_statement_template_is_mutable(self):
        stmt = await create_tix_statement_template()
        stmt["products"].append({"test": "product"})

        original = tix_stmt_template()
        assert len(original["products"]) == 1


class TestTemplateCaching:
    def test_vex_template_is_cached(self):
        tmpl1 = template()
        tmpl2 = template()

        assert tmpl1 is tmpl2

    def test_tix_template_is_cached(self):
        tmpl1 = tix_template()
        tmpl2 = tix_template()

        assert tmpl1 is tmpl2

    def test_vex_statement_template_is_cached(self):
        stmt1 = vex_stmt_template()
        stmt2 = vex_stmt_template()

        assert stmt1 is stmt2

    def test_tix_statement_template_is_cached(self):
        stmt1 = tix_stmt_template()
        stmt2 = tix_stmt_template()

        assert stmt1 is stmt2
