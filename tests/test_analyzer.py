import pytest
import os
import tempfile
from capstone import *
from analyzer import PEAnalyzer
from reporter import PEReporter


def get_test_files():
    """Получаем пути к тестовым PE файлам"""
    test_dir = os.path.join(os.path.dirname(__file__), '..', 'test_files')
    test_files = [
        os.path.join(test_dir, 'calc.exe'),
        os.path.join(test_dir, 'notepad.exe')
    ]
    return [f for f in test_files if os.path.exists(f)]


@pytest.fixture(params=get_test_files())
def pe_analyzer(request):
    """
    Фикстура для создания объекта PEAnalyzer и проведения анализа.
    Аналогично тому, как раньше создавали PEFile.
    """
    test_file = request.param
    analyzer = PEAnalyzer(test_file)
    analyzer.analyze()
    return analyzer


@pytest.fixture
def temp_output_file():
    """Фикстура для создания временного файла вывода"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        temp_path = f.name
    yield temp_path
    os.unlink(temp_path)


def test_section_headers(pe_analyzer):
    """Тест заголовков секций"""
    assert len(pe_analyzer.sections) > 0

    for section in pe_analyzer.sections:
        assert isinstance(section.name, str)
        assert len(section.name) > 0
        assert section.virtual_address >= 0
        assert section.virtual_size > 0
        assert section.raw_size >= 0
        assert section.raw_offset >= 0


def test_machine_code_disassembly(pe_analyzer):
    """Тест дизассемблирования машинного кода с помощью Capstone"""
    code_section = next((s for s in pe_analyzer.sections if s.name.lower() == '.text'), None)
    if not code_section:
        pytest.skip("Секция .text не найдена")

    with open(pe_analyzer.filepath, 'rb') as f:
        f.seek(code_section.raw_offset)
        code = f.read(min(code_section.raw_size, 1024))

    md = Cs(CS_ARCH_X86, CS_MODE_64 if pe_analyzer.machine == 0x8664 else CS_MODE_32)
    capstone_instructions = list(md.disasm(code, code_section.virtual_address))

    assert len(capstone_instructions) > 0

    if code_section.machine_code:
        mc = code_section.machine_code
        assert mc['virtual_address'] == code_section.virtual_address
        assert mc['physical_address'] == code_section.raw_offset
        assert mc['size'] == code_section.raw_size

        actual_bytes = bytes.fromhex(mc['first_bytes'].replace(' ', ''))
        assert len(actual_bytes) == min(32, len(code))
        assert actual_bytes == code[:len(actual_bytes)]


def test_imports(pe_analyzer):
    """Тест таблицы импортов"""
    assert len(pe_analyzer.imports) > 0

    for dll, functions in pe_analyzer.imports.items():
        assert isinstance(dll, str)
        assert dll.lower().endswith('.dll')

        assert isinstance(functions, list)
        assert len(functions) > 0

        for func in functions:
            assert isinstance(func, str)
            assert len(func) > 0


def test_debug_output(capsys):
    """Тест отладочного вывода через PEReporter"""
    test_file = get_test_files()[0]

    analyzer = PEAnalyzer(test_file)
    analyzer.analyze()

    reporter_no_debug = PEReporter(analyzer, debug=False)
    reporter_no_debug.debug_print("Test message (no debug)")
    captured = capsys.readouterr()
    assert captured.out == ""

    reporter_debug = PEReporter(analyzer, debug=True)
    reporter_debug.debug_print("Test message (with debug)")
    captured = capsys.readouterr()
    assert captured.out == "DEBUG: Test message (with debug)\n"


def test_file_output(temp_output_file):
    """Тест вывода в файл (reporter.output_file)"""
    test_file = get_test_files()[0]

    analyzer = PEAnalyzer(test_file)
    analyzer.analyze()

    reporter = PEReporter(analyzer, debug=True, output_file=temp_output_file)
    reporter.debug_print("Test debug message")
    reporter.print_info()

    with open(temp_output_file, 'r', encoding='utf-8') as f:
        content = f.read()

    assert "DEBUG: Test debug message" in content
    assert "Анализ файла:" in content
    assert "Основная информация:" in content
    assert "Секции:" in content
    assert "Машинный код:" in content
    assert "Таблица импортов:" in content


def test_multiple_file_outputs(temp_output_file):
    """Тест множественного вывода в один и тот же файл"""
    test_files = get_test_files()

    for test_file in test_files:
        analyzer = PEAnalyzer(test_file)
        analyzer.analyze()

        reporter = PEReporter(analyzer, debug=True, output_file=temp_output_file)
        reporter.debug_print(f"Analyzing {test_file}")
        reporter.print_info()

    with open(temp_output_file, 'r', encoding='utf-8') as f:
        content = f.read()

    for test_file in test_files:
        assert f"Analyzing {test_file}" in content
        assert os.path.basename(test_file) in content


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
