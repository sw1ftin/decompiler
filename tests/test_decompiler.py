import pytest
import os
import struct
import tempfile
from capstone import *
from decompiler import PEFile

def get_test_files():
    """Получаем пути к тестовым PE файлам"""
    test_dir = os.path.join(os.path.dirname(__file__), '..', 'test_files')
    test_files = [
        os.path.join(test_dir, 'calc.exe'),
        os.path.join(test_dir, 'notepad.exe')
    ]
    return [f for f in test_files if os.path.exists(f)]

@pytest.fixture(params=get_test_files())
def pe_file(request):
    """Фикстура для создания объекта PE файла"""
    test_file = request.param
    pe = PEFile(test_file, debug=False)
    pe.analyze()
    return pe

@pytest.fixture
def temp_output_file():
    """Фикстура для создания временного файла вывода"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        temp_path = f.name
    yield temp_path
    os.unlink(temp_path)

def test_section_headers(pe_file):
    """Тест заголовков секций"""
    # Проверяем, что секции существуют
    assert len(pe_file.sections) > 0
    
    # Проверяем корректность значений для каждой секции
    for section in pe_file.sections:
        assert isinstance(section['name'], str)
        assert len(section['name']) > 0
        assert section['virtual_address'] >= 0
        assert section['virtual_size'] > 0
        assert section['raw_size'] >= 0
        assert section['raw_offset'] >= 0

def test_machine_code_disassembly(pe_file):
    """Тест дизассемблирования машинного кода"""
    # Находим секцию с кодом (обычно .text)
    code_section = next((s for s in pe_file.sections if s['name'].lower() == '.text'), None)
    if not code_section:
        pytest.skip("Секция .text не найдена")
    
    # Читаем машинный код из файла
    with open(pe_file.filepath, 'rb') as f:
        f.seek(code_section['raw_offset'])
        code = f.read(min(code_section['raw_size'], 1024))  # Читаем первый 1KB
    
    # Инициализируем Capstone
    md = Cs(CS_ARCH_X86, CS_MODE_64 if pe_file.machine == 0x8664 else CS_MODE_32)
    
    # Дизассемблируем с помощью Capstone
    capstone_instructions = list(md.disasm(code, code_section['virtual_address']))
    
    # Проверяем, что Capstone смог разобрать код
    assert len(capstone_instructions) > 0
    
    # Проверяем машинный код из нашего декомпилятора
    if 'machine_code' in code_section:
        mc = code_section['machine_code']
        # Проверяем, что адреса и размеры совпадают
        assert mc['virtual_address'] == code_section['virtual_address']
        assert mc['physical_address'] == code_section['raw_offset']
        assert mc['size'] == code_section['raw_size']
        
        # Проверяем первые байты
        actual_bytes = bytes.fromhex(mc['first_bytes'].replace(' ', ''))
        assert len(actual_bytes) == min(32, len(code))
        assert actual_bytes == code[:len(actual_bytes)]

def test_imports(pe_file):
    """Тест импортов"""
    # Проверяем, что импорты существуют
    assert len(pe_file.imports) > 0
    
    # Проверяем структуру импортов
    for dll, functions in pe_file.imports.items():
        # Проверяем имя DLL
        assert isinstance(dll, str)
        assert dll.lower().endswith('.dll')
        
        # Проверяем функции
        assert isinstance(functions, list)
        assert len(functions) > 0
        
        # Проверяем каждую функцию
        for func in functions:
            assert isinstance(func, str)
            assert len(func) > 0

def test_debug_output(capsys):
    """Тест отладочного вывода"""
    test_file = get_test_files()[0]
    
    # Тест без отладочного вывода
    pe = PEFile(test_file, debug=False)
    pe.debug_print("Test message")
    captured = capsys.readouterr()
    assert captured.out == ""
    
    # Тест с отладочным выводом
    pe = PEFile(test_file, debug=True)
    pe.debug_print("Test message")
    captured = capsys.readouterr()
    assert captured.out == "DEBUG: Test message\n"

def test_file_output(temp_output_file):
    """Тест вывода в файл"""
    test_file = get_test_files()[0]
    
    # Создаем объект PE с выводом в файл
    pe = PEFile(test_file, debug=True, output_file=temp_output_file)
    pe.debug_print("Test debug message")
    pe.analyze()
    pe.print_info()
    
    # Проверяем содержимое файла
    with open(temp_output_file, 'r', encoding='utf-8') as f:
        content = f.read()
        
    # Проверяем наличие основной информации
    assert "DEBUG: Test debug message" in content
    assert "Анализ файла:" in content
    assert "Основная информация:" in content
    assert "Секции:" in content
    assert "Машинный код:" in content
    assert "Таблица импортов:" in content

def test_multiple_file_outputs(temp_output_file):
    """Тест множественного вывода в файл"""
    test_files = get_test_files()
    
    # Анализируем несколько файлов с выводом в один файл
    for test_file in test_files:
        pe = PEFile(test_file, debug=True, output_file=temp_output_file)
        pe.debug_print(f"Analyzing {test_file}")
        pe.analyze()
        pe.print_info()
    
    # Проверяем содержимое файла
    with open(temp_output_file, 'r', encoding='utf-8') as f:
        content = f.read()
        
    # Проверяем, что информация о каждом файле присутствует
    for test_file in test_files:
        assert f"Analyzing {test_file}" in content
        assert os.path.basename(test_file) in content

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
