# analyzer.py

import struct
from dataclasses import dataclass, field


@dataclass(frozen=True)
class PEConstants:
    """Константы, связанные с PE-форматом."""
    PE32_DATA_DIR_OFFSET: int = 96
    PE32PLUS_DATA_DIR_OFFSET: int = 112
    IMPORT_TABLE_RVA_OFFSET: int = 8
    DOS_SIGNATURE_OFFSET: int = 0x3C
    IMPORT_DIRECTORY_ENTRY_SIZE: int = 20
    HINT_SIZE: int = 2
    DOS_SIGNATURE: bytes = b'MZ'
    PE_SIGNATURE: bytes = b'PE\x00\x00'

    NULL_CHAR_BYTE: bytes = b'\x00'
    PE32PLUS_FORMAT: int = 0x20B
    PE32_FORMAT: int = 0x10B

    ORDINAL_FLAG_32: int = 0x80000000
    ORDINAL_FLAG_64: int = 0x8000000000000000
    MASK_32: int = 0x7FFFFFFF
    MASK_64: int = 0x7FFFFFFFFFFFFFFF
    ORDINAL_MASK: int = 0xFFFF


@dataclass
class SectionData:
    """Структура для хранения данных об одной секции PE-файла."""
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_offset: int
    machine_code: dict | None = field(default=None)


@dataclass
class ImportDirectoryEntry:
    """Структура для хранения записи в таблице импортов."""
    import_lookup_table_rva: int
    timestamp: int
    forwarder_chain: int
    name_rva: int
    thunk_rva: int

    def is_empty(self) -> bool:
        """Проверяет, является ли запись пустой (конец таблицы)."""
        return (self.import_lookup_table_rva == 0 and 
                self.name_rva == 0 and 
                self.thunk_rva == 0)


class ImportDirectoryEntryFactory:
    """Фабрика для создания объектов ImportDirectoryEntry."""
    
    @staticmethod
    def from_file(file_obj) -> ImportDirectoryEntry:
        """Создает объект ImportDirectoryEntry из файла."""
        try:
            values = struct.unpack('<IIIII', file_obj.read(PEConstants.IMPORT_DIRECTORY_ENTRY_SIZE))
            return ImportDirectoryEntry(*values)
        except struct.error as e:
            raise ValueError(f"Ошибка чтения Import Directory Entry: {e}")


class PEAnalyzer:
    def __init__(self, filepath: str):
        """Анализатор PE-файла. Считывает DOS-заголовок, PE-заголовок, секции и таблицу импортов."""
        self._filepath: str = filepath
        self._sections: list[SectionData] = []
        self._imports: dict[str, list[str]] = {}
        self._consts = PEConstants()

        # Приватные поля заголовков
        self._machine: int | None = None
        self._num_sections: int | None = None
        self._timestamp: int | None = None
        self._pe_offset: int | None = None
        self._optional_header_size: int | None = None
        self._characteristics: int | None = None
        self._optional_header_offset: int | None = None
        self._section_table_offset: int | None = None
        self._pe_format: int | None = None
        self._size_of_code: int | None = None
        self._size_of_initialized_data: int | None = None
        self._size_of_uninitialized_data: int | None = None
        self._entry_point: int | None = None
        self._base_of_code: int | None = None
        self._base_of_data: int | None = None
        self._image_base: int | None = None

    @property
    def filepath(self) -> str:
        return self._filepath

    @property
    def sections(self) -> list[SectionData]:
        """Возвращает список секций."""
        return self._sections

    @property
    def imports(self) -> dict[str, list[str]]:
        """Возвращает словарь импортов."""
        return self._imports

    @property
    def machine(self) -> int | None:
        """Возвращает тип платформы (Machine) из COFF-заголовка."""
        return self._machine

    @property
    def num_sections(self) -> int | None:
        """Возвращает количество секций в PE-файле."""
        return self._num_sections

    @property
    def timestamp(self) -> int | None:
        """Возвращает timestamp (время сборки) из COFF-заголовка."""
        return self._timestamp

    @property
    def pe_format(self) -> int | None:
        """Возвращает Magic: 0x10B (PE32) или 0x20B (PE32+)."""
        return self._pe_format

    def analyze(self) -> None:
        """Полный анализ PE-файла: заголовки, секции, машина, импорты."""
        self._read_dos_header()
        self._read_pe_header()
        self._read_sections()
        self._read_machine_code()
        self._read_imports()

    def _read_dos_header(self) -> None:
        """Чтение DOS-заголовка (MZ) и определение смещения PE-заголовка."""
        try:
            with open(self._filepath, 'rb') as f:
                dos_signature = f.read(2)
                if dos_signature != self._consts.DOS_SIGNATURE:
                    raise ValueError("Неверная DOS сигнатура (MZ)")

                f.seek(self._consts.DOS_SIGNATURE_OFFSET)
                self._pe_offset = struct.unpack('<I', f.read(4))[0]
        except (IOError, struct.error) as e:
            raise ValueError(f"Ошибка чтения DOS заголовка: {e}")

    def _read_pe_header(self) -> None:
        """Чтение COFF и Optional Header. Определение смещения к таблице секций."""
        try:
            with open(self._filepath, 'rb') as f:
                f.seek(self._pe_offset or 0)
                pe_signature = f.read(4)
                if pe_signature != self._consts.PE_SIGNATURE:
                    raise ValueError("Неверная PE сигнатура")

                self._read_coff_header(f)
                self._read_optional_header(f)
                self._section_table_offset = f.tell()
        except (IOError, struct.error) as e:
            raise ValueError(f"Ошибка чтения PE заголовка: {e}")

    def _read_coff_header(self, file_obj) -> None:
        """Чтение COFF заголовка."""
        self._machine = struct.unpack('<H', file_obj.read(2))[0]
        self._num_sections = struct.unpack('<H', file_obj.read(2))[0]
        self._timestamp = struct.unpack('<I', file_obj.read(4))[0]
        file_obj.seek(8, 1)  # Пропускаем PointerToSymbolTable и NumberOfSymbols
        self._optional_header_size = struct.unpack('<H', file_obj.read(2))[0]
        self._characteristics = struct.unpack('<H', file_obj.read(2))[0]
        self._optional_header_offset = file_obj.tell()

    def _read_optional_header(self, file_obj) -> None:
        """Чтение Optional Header."""
        self._pe_format = struct.unpack('<H', file_obj.read(2))[0]
        file_obj.seek(2, 1)  # Пропускаем LinkerVersion

        # Читаем базовые поля
        (self._size_of_code, self._size_of_initialized_data,
         self._size_of_uninitialized_data, self._entry_point,
         self._base_of_code) = struct.unpack('<IIIII', file_obj.read(20))

        if self._pe_format == self._consts.PE32_FORMAT:
            self._base_of_data = struct.unpack('<I', file_obj.read(4))[0]
            self._image_base = struct.unpack('<I', file_obj.read(4))[0]
        else:
            self._image_base = struct.unpack('<Q', file_obj.read(8))[0]

        # Пропускаем оставшуюся часть Optional Header
        read_so_far = file_obj.tell() - self._optional_header_offset
        remaining_bytes = self._optional_header_size - read_so_far
        if remaining_bytes > 0:
            file_obj.seek(remaining_bytes, 1)

    def _read_sections(self) -> None:
        """Чтение таблицы секций (Section Table)."""
        with open(self._filepath, 'rb') as f:
            f.seek(self._section_table_offset or 0)

            for _ in range(self._num_sections or 0):
                name_bytes = f.read(8)
                name = name_bytes.rstrip(self._consts.NULL_CHAR_BYTE).decode('ascii', errors='replace') or '.unknown'

                virtual_size = struct.unpack('<I', f.read(4))[0]
                virtual_address = struct.unpack('<I', f.read(4))[0]
                raw_size = struct.unpack('<I', f.read(4))[0]
                raw_offset = struct.unpack('<I', f.read(4))[0]

                # Пропускаем оставшиеся 16 байт структуры IMAGE_SECTION_HEADER
                f.seek(16, 1)

                section = SectionData(
                    name=name,
                    virtual_size=virtual_size,
                    virtual_address=virtual_address,
                    raw_size=raw_size,
                    raw_offset=raw_offset,
                )
                self._sections.append(section)

    def _read_machine_code(self) -> None:
        """Чтение первых 32 байт машинного кода каждой секции (если raw_size > 0)."""
        with open(self._filepath, 'rb') as f:
            for section in self._sections:
                if section.raw_size > 0:
                    f.seek(section.raw_offset)
                    code_size = min(32, section.raw_size)
                    code_data = f.read(code_size)
                    section.machine_code = {
                        'virtual_address': section.virtual_address,
                        'physical_address': section.raw_offset,
                        'size': section.raw_size,
                        'first_bytes': ' '.join(f'{b:02X}' for b in code_data)
                    }

    def _read_imports(self) -> None:
        """Разбор таблицы импортов (Import Directory)."""
        with open(self._filepath, 'rb') as f:
            data_dir_offset = self._get_data_directory_offset()
            f.seek(data_dir_offset + self._consts.IMPORT_TABLE_RVA_OFFSET)
            try:
                import_table_rva = struct.unpack('<I', f.read(4))[0]
                import_table_size = struct.unpack('<I', f.read(4))[0]
            except struct.error:
                return

            if import_table_rva == 0:
                return

            import_table_offset = self._rva_to_offset(import_table_rva)
            if import_table_offset is None:
                return

            self._parse_import_table(f, import_table_offset)

    def _get_data_directory_offset(self) -> int:
        """
        Определяем смещение Data Directory относительно начала Optional Header
        для Import Directory. Зависит от формата PE: PE32 или PE32+.
        """
        if self._pe_format == self._consts.PE32PLUS_FORMAT:
            return (self._optional_header_offset or 0) + self._consts.PE32PLUS_DATA_DIR_OFFSET
        else:
            return (self._optional_header_offset or 0) + self._consts.PE32_DATA_DIR_OFFSET

    def _parse_import_table(self, file_obj, import_table_offset: int) -> None:
        """Читает Import Directory Table построчно и вызывает `_parse_import_functions()` для каждой записи."""
        current_offset = import_table_offset
        dll_entry_size = 20  # Размер одной записи Import Directory

        while True:
            file_obj.seek(current_offset)
            try:
                import_lookup_table_rva = struct.unpack('<I', file_obj.read(4))[0]
                timestamp = struct.unpack('<I', file_obj.read(4))[0]
                forwarder_chain = struct.unpack('<I', file_obj.read(4))[0]
                name_rva = struct.unpack('<I', file_obj.read(4))[0]
                thunk_rva = struct.unpack('<I', file_obj.read(4))[0]
            except struct.error:
                break

            # Пустая запись — конец
            if import_lookup_table_rva == 0 and name_rva == 0 and thunk_rva == 0:
                break

            dll_name_offset = self._rva_to_offset(name_rva)
            if dll_name_offset is None:
                current_offset += dll_entry_size
                continue

            file_obj.seek(dll_name_offset)
            dll_name = self._read_string(file_obj)
            if not dll_name:
                current_offset += dll_entry_size
                continue

            self._imports[dll_name] = []

            lookup_rva = import_lookup_table_rva if import_lookup_table_rva != 0 else thunk_rva
            lookup_offset = self._rva_to_offset(lookup_rva)
            if lookup_offset is None:
                current_offset += dll_entry_size
                continue

            self._parse_import_functions(file_obj, dll_name, lookup_offset)
            current_offset += dll_entry_size

    def _parse_import_functions(self, file_obj, dll_name: str, lookup_offset: int) -> None:
        """Читает список функций (или ординалов), связанных с конкретной Import Lookup/Address Table."""
        try:
            file_obj.seek(lookup_offset)
            ordinal_flag, mask = self._get_ordinal_and_mask_for_pe()

            while True:
                thunk_data = self._read_thunk_data(file_obj)
                if thunk_data == 0:
                    break

                if thunk_data & ordinal_flag:
                    self._add_ordinal_import(dll_name, thunk_data)
                else:
                    self._add_name_import(file_obj, dll_name, thunk_data, mask)
        except (IOError, struct.error) as e:
            raise ValueError(f"Ошибка чтения функций импорта: {e}")

    def _read_thunk_data(self, file_obj) -> int:
        """Читает ThunkData в зависимости от формата PE."""
        if self._pe_format == self._consts.PE32PLUS_FORMAT:
            return struct.unpack('<Q', file_obj.read(8))[0]
        return struct.unpack('<I', file_obj.read(4))[0]

    def _add_ordinal_import(self, dll_name: str, thunk_data: int) -> None:
        """Добавляет импорт по ординалу."""
        ordinal = thunk_data & self._consts.ORDINAL_MASK
        self._imports[dll_name].append(f"#{ordinal}")

    def _add_name_import(self, file_obj, dll_name: str, thunk_data: int, mask: int) -> None:
        """Добавляет импорт по имени."""
        hint_name_rva = thunk_data & mask
        name_offset = self._rva_to_offset(hint_name_rva)
        if name_offset is not None:
            file_obj.seek(name_offset + self._consts.HINT_SIZE)
            func_name = self._read_string(file_obj)
            if func_name:
                self._imports[dll_name].append(func_name)

    def _get_ordinal_and_mask_for_pe(self) -> tuple[int, int]:
        """Возвращает (ordinal_flag, mask), специфичные для PE32 или PE32+."""
        if self._pe_format == self._consts.PE32PLUS_FORMAT:
            return self._consts.ORDINAL_FLAG_64, self._consts.MASK_64
        else:
            return self._consts.ORDINAL_FLAG_32, self._consts.MASK_32

    def _rva_to_offset(self, rva: int) -> int | None:
        """Конвертация RVA в файловое смещение на основе таблицы секций."""
        for section in self._sections:
            start_rva = section.virtual_address
            end_rva = start_rva + section.virtual_size
            if start_rva <= rva < end_rva:
                return rva - start_rva + section.raw_offset
        return None

    @staticmethod
    def _read_string(file_obj) -> str:
        """Чтение null-terminated ASCII-строки из потока."""
        result = []
        while True:
            char = file_obj.read(1)
            if not char or char == PEConstants.NULL_CHAR_BYTE:
                break
            try:
                result.append(char.decode('ascii'))
            except UnicodeDecodeError:
                break
        return ''.join(result)
