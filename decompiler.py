import os
import struct
import click
from rich.console import Console
from rich.table import Table
from datetime import datetime

console = Console()

class PEFile:
    def __init__(self, filepath, debug=False, output_file=None):
        self.filepath = filepath
        self.sections = []
        self.imports = {}
        self.debug = debug
        self.output_file = output_file
        self.output_buffer = []
        
    def debug_print(self, message):
        """Вывод отладочной информации"""
        if self.debug:
            debug_msg = f"DEBUG: {message}"
            if self.output_file:
                self.output_buffer.append(debug_msg)
            else:
                print(debug_msg)
                
    def write_output(self):
        """Записывает накопленный вывод в файл"""
        if self.output_file and self.output_buffer:
            with open(self.output_file, 'a', encoding='utf-8') as f:
                f.write(f"\n=== Анализ {self.filepath} ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')}) ===\n")
                f.write('\n'.join(self.output_buffer))
                f.write("\n")
            self.output_buffer = []
            
    def print_info(self):
        """Вывод информации о файле"""
        if self.output_file:
            # Создаем временную консоль для записи в строку
            str_console = Console(record=True)
            self._print_info_to_console(str_console)
            self.output_buffer.append(str_console.export_text())
            self.write_output()
        else:
            self._print_info_to_console(console)
            
    def _print_info_to_console(self, output_console):
        """Вывод информации в указанную консоль"""
        output_console.print(f"\n[bold blue]Анализ файла:[/bold blue] {self.filepath}")
        
        # Вывод основной информации
        output_console.print(f"\n[bold green]Основная информация:[/bold green]")
        output_console.print(f"Machine: {hex(self.machine)}")
        output_console.print(f"Количество секций: {self.num_sections}")
        output_console.print(f"Timestamp: {self.timestamp}")
        
        # Вывод информации о секциях
        output_console.print(f"\n[bold green]Секции:[/bold green]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Имя", style="cyan")
        table.add_column("Virtual Size", style="green")
        table.add_column("Virtual Address", style="yellow")
        table.add_column("Raw Size", style="red")
        table.add_column("Raw Offset", style="blue")
        
        for section in self.sections:
            table.add_row(
                section['name'],
                hex(section['virtual_size']),
                hex(section['virtual_address']),
                hex(section['raw_size']),
                hex(section['raw_offset'])
            )
        output_console.print(table)
        
        # Вывод машинного кода
        output_console.print(f"\n[bold green]Машинный код:[/bold green]")
        for i, section in enumerate(self.sections, 1):
            if 'machine_code' in section and section['raw_size'] > 0:
                mc = section['machine_code']
                output_console.print(f"\nМашинный код #{i} (секция {section['name']}):")
                output_console.print(f"  Виртуальный адрес: {hex(mc['virtual_address'])}")
                output_console.print(f"  Физический адрес: {hex(mc['physical_address'])}")
                output_console.print(f"  Размер: {mc['size']} байт")
                output_console.print(f"  Первые 32 байта:")
                output_console.print(f"   {mc['first_bytes']}")
        
        # Вывод информации об импортах
        if self.imports:
            output_console.print(f"\n[bold green]Таблица импортов:[/bold green]")
            for dll, functions in self.imports.items():
                output_console.print(f"\n[yellow]{dll}:[/yellow]")
                functions_str = ", ".join(functions)
                output_console.print(f"  {functions_str}")
                
    def analyze(self):
        """Полный анализ файла"""
        self.read_dos_header()
        self.read_pe_header()
        self.read_sections()
        self.read_machine_code()
        self.read_imports()
        if self.output_file:
            self.write_output()

    def read_dos_header(self):
        """Чтение DOS заголовка"""
        with open(self.filepath, 'rb') as f:
            # Читаем сигнатуру DOS (MZ)
            dos_signature = f.read(2)
            if dos_signature != b'MZ':
                raise ValueError("Неверная DOS сигнатура")
            
            # Пропускаем до e_lfanew (смещение PE заголовка)
            f.seek(0x3C)
            self.pe_offset = struct.unpack('<I', f.read(4))[0]
            
    def read_pe_header(self):
        """Чтение PE заголовка"""
        with open(self.filepath, 'rb') as f:
            f.seek(self.pe_offset)
            
            # Проверка PE сигнатуры
            pe_signature = f.read(4)
            if pe_signature != b'PE\x00\x00':
                raise ValueError("Неверная PE сигнатура")
            
            # Чтение COFF заголовка
            self.machine = struct.unpack('<H', f.read(2))[0]
            self.num_sections = struct.unpack('<H', f.read(2))[0]
            self.timestamp = struct.unpack('<I', f.read(4))[0]
            
            self.debug_print(f"Machine: {hex(self.machine)}")
            self.debug_print(f"Number of sections: {self.num_sections}")
            
            # Пропускаем Symbol Table Pointer и Number of Symbols
            f.seek(8, 1)
            
            # Размер опционального заголовка
            self.optional_header_size = struct.unpack('<H', f.read(2))[0]
            self.characteristics = struct.unpack('<H', f.read(2))[0]
            self.optional_header_offset = f.tell()
            
            self.debug_print(f"Optional header size: {hex(self.optional_header_size)}")
            self.debug_print(f"Optional header offset: {hex(self.optional_header_offset)}")
            
            # Читаем Magic из опционального заголовка для определения формата PE32/PE32+
            self.pe_format = struct.unpack('<H', f.read(2))[0]
            self.debug_print(f"PE Format: {hex(self.pe_format)}")
            
            # Пропускаем LinkerVersion
            f.seek(2, 1)
            
            # Читаем размеры
            self.size_of_code = struct.unpack('<I', f.read(4))[0]
            self.size_of_initialized_data = struct.unpack('<I', f.read(4))[0]
            self.size_of_uninitialized_data = struct.unpack('<I', f.read(4))[0]
            self.entry_point = struct.unpack('<I', f.read(4))[0]
            self.base_of_code = struct.unpack('<I', f.read(4))[0]
            
            # Для PE32+ нет base_of_data
            if self.pe_format == 0x10b:  # PE32
                self.base_of_data = struct.unpack('<I', f.read(4))[0]
                self.image_base = struct.unpack('<I', f.read(4))[0]
            else:  # PE32+
                self.image_base = struct.unpack('<Q', f.read(8))[0]
            
    def read_sections(self):
        """Чтение секций"""
        with open(self.filepath, 'rb') as f:
            # Переходим к таблице секций (после опционального заголовка)
            section_table_offset = self.optional_header_offset + self.optional_header_size
            f.seek(section_table_offset)
            
            self.debug_print(f"Section table offset: {hex(section_table_offset)}")
            self.debug_print(f"Number of sections to read: {self.num_sections}")
            
            for i in range(self.num_sections):
                section = {}
                
                # Чтение имени секции (8 байт)
                name_bytes = f.read(8)
                try:
                    # Удаляем нулевые байты и декодируем
                    name = name_bytes.rstrip(b'\x00').decode('ascii')
                    section['name'] = name if name else '.unknown'
                except:
                    section['name'] = '.unknown'
                
                # Чтение остальных полей секции
                section['virtual_size'] = struct.unpack('<I', f.read(4))[0]
                section['virtual_address'] = struct.unpack('<I', f.read(4))[0]
                section['raw_size'] = struct.unpack('<I', f.read(4))[0]
                section['raw_offset'] = struct.unpack('<I', f.read(4))[0]
                
                self.debug_print(f"Section {i + 1}:")
                self.debug_print(f"  Name: {section['name']}")
                self.debug_print(f"  Virtual Size: {hex(section['virtual_size'])}")
                self.debug_print(f"  Virtual Address: {hex(section['virtual_address'])}")
                self.debug_print(f"  Raw Size: {hex(section['raw_size'])}")
                self.debug_print(f"  Raw Offset: {hex(section['raw_offset'])}")
                
                # Пропускаем оставшиеся поля секции
                f.seek(16, 1)  # Пропускаем 16 байт (остальные поля)
                
                # Добавляем секцию, если она имеет размер
                if section['raw_size'] > 0:
                    self.sections.append(section)
                    
            self.debug_print(f"Total sections added: {len(self.sections)}")
                    
    def read_machine_code(self):
        """Чтение машинного кода из секций"""
        with open(self.filepath, 'rb') as f:
            for section in self.sections:
                if section['raw_size'] > 0:
                    f.seek(section['raw_offset'])
                    code_size = min(32, section['raw_size'])
                    code = f.read(code_size)
                    section['machine_code'] = {
                        'virtual_address': section['virtual_address'],
                        'physical_address': section['raw_offset'],
                        'size': section['raw_size'],
                        'first_bytes': ' '.join(f'{b:02X}' for b in code)
                    }
                    
    def read_imports(self):
        """Чтение таблицы импорта"""
        with open(self.filepath, 'rb') as f:
            # Определяем смещение до DataDirectory в зависимости от формата PE
            if self.pe_format == 0x20B:  # PE32+
                data_directory_offset = self.optional_header_offset + 112
            else:  # PE32
                data_directory_offset = self.optional_header_offset + 96
            
            self.debug_print(f"Data directory offset: {hex(data_directory_offset)}")
            
            # Читаем RVA и размер таблицы импорта
            f.seek(data_directory_offset + 8)  # Import Directory RVA
            import_table_rva = struct.unpack('<I', f.read(4))[0]
            import_table_size = struct.unpack('<I', f.read(4))[0]
            
            self.debug_print(f"Import table RVA: {hex(import_table_rva)}")
            self.debug_print(f"Import table size: {hex(import_table_size)}")
            
            if import_table_rva == 0:
                self.debug_print("No import table found")
                return
                
            # Преобразуем RVA в файловое смещение
            import_table_offset = self._rva_to_offset(import_table_rva)
            if import_table_offset is None:
                self.debug_print("Could not convert import table RVA to file offset")
                return
                
            self.debug_print(f"Import table file offset: {hex(import_table_offset)}")
            
            # Читаем каждую запись в таблице импорта
            current_offset = import_table_offset
            while True:
                f.seek(current_offset)
                
                # Читаем Import Directory Table entry
                try:
                    import_lookup_table_rva = struct.unpack('<I', f.read(4))[0]
                    timestamp = struct.unpack('<I', f.read(4))[0]
                    forwarder_chain = struct.unpack('<I', f.read(4))[0]
                    name_rva = struct.unpack('<I', f.read(4))[0]
                    thunk_rva = struct.unpack('<I', f.read(4))[0]
                except struct.error:
                    self.debug_print("Error reading import directory entry")
                    break
                    
                self.debug_print(f"Import entry at {hex(current_offset)}:")
                self.debug_print(f"  Lookup Table RVA: {hex(import_lookup_table_rva)}")
                self.debug_print(f"  Name RVA: {hex(name_rva)}")
                self.debug_print(f"  Thunk RVA: {hex(thunk_rva)}")
                
                # Если все поля нулевые или некорректные, заканчиваем
                if import_lookup_table_rva == 0 and name_rva == 0 and thunk_rva == 0:
                    self.debug_print("Reached end of import table")
                    break
                    
                # Читаем имя DLL
                dll_name_offset = self._rva_to_offset(name_rva)
                if dll_name_offset is None:
                    self.debug_print(f"Could not convert DLL name RVA {hex(name_rva)} to file offset")
                    current_offset += 20
                    continue
                    
                f.seek(dll_name_offset)
                dll_name = self._read_string(f)
                if not dll_name:
                    self.debug_print("Could not read DLL name")
                    current_offset += 20
                    continue
                    
                self.debug_print(f"Found DLL: {dll_name}")
                
                # Инициализируем список функций для этой DLL
                self.imports[dll_name] = []
                
                # Используем Import Lookup Table или Import Address Table
                lookup_rva = import_lookup_table_rva if import_lookup_table_rva != 0 else thunk_rva
                lookup_offset = self._rva_to_offset(lookup_rva)
                if lookup_offset is None:
                    self.debug_print(f"Could not convert lookup RVA {hex(lookup_rva)} to file offset")
                    current_offset += 20
                    continue
                    
                f.seek(lookup_offset)
                self.debug_print(f"Reading functions from offset {hex(lookup_offset)}")
                
                # Читаем функции
                while True:
                    try:
                        # Читаем элемент таблицы (32 или 64 бита)
                        if self.pe_format == 0x20B:  # PE32+
                            thunk_data = struct.unpack('<Q', f.read(8))[0]
                            ordinal_flag = 0x8000000000000000
                        else:  # PE32
                            thunk_data = struct.unpack('<I', f.read(4))[0]
                            ordinal_flag = 0x80000000
                            
                        if thunk_data == 0:
                            break
                            
                        if thunk_data & ordinal_flag:
                            # Импорт по ординалу
                            ordinal = thunk_data & 0xFFFF
                            self.imports[dll_name].append(f"#{ordinal}")
                            self.debug_print(f"Found ordinal import: #{ordinal}")
                        else:
                            # Импорт по имени
                            hint_name_rva = thunk_data & (0x7FFFFFFFFFFFFFFF if self.pe_format == 0x20B else 0x7FFFFFFF)
                            name_offset = self._rva_to_offset(hint_name_rva)
                            if name_offset is not None:
                                f.seek(name_offset + 2)  # Пропускаем Hint
                                func_name = self._read_string(f)
                                if func_name:
                                    self.imports[dll_name].append(func_name)
                                    self.debug_print(f"Found function: {func_name}")
                    except Exception as e:
                        self.debug_print(f"Error reading function: {str(e)}")
                        break
                        
                current_offset += 20
                
            self.debug_print(f"Total DLLs found: {len(self.imports)}")
            for dll, funcs in self.imports.items():
                self.debug_print(f"{dll}: {len(funcs)} functions")
                
    def _rva_to_offset(self, rva):
        """Конвертация RVA в файловое смещение"""
        for section in self.sections:
            if section['virtual_address'] <= rva < section['virtual_address'] + section['virtual_size']:
                return rva - section['virtual_address'] + section['raw_offset']
        return None
        
    def _read_string(self, f):
        """Чтение null-terminated строки"""
        try:
            result = []
            while True:
                char = f.read(1)
                if not char or char == b'\x00':
                    break
                result.append(char.decode('ascii'))
            return ''.join(result)
        except:
            return ''

@click.command()
@click.argument('filepath', type=click.Path(exists=True))
@click.option('--debug', is_flag=True, help='Включить отладочный вывод')
@click.option('--output', '-o', type=click.Path(), help='Файл для сохранения результатов')
def main(filepath, debug, output):
    """Декомпилятор EXE файлов"""
    try:
        pe_file = PEFile(filepath, debug=debug, output_file=output)
        pe_file.analyze()
        pe_file.print_info()
    except Exception as e:
        error_msg = f"[bold red]Ошибка:[/bold red] {str(e)}"
        if output:
            with open(output, 'a', encoding='utf-8') as f:
                f.write(f"\nОШИБКА: {str(e)}\n")
        else:
            console.print(error_msg)

if __name__ == '__main__':
    main()
