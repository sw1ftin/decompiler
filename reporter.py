# reporter.py

from rich.console import Console
from rich.table import Table
from datetime import datetime

class PEReporter:
    def __init__(self, analyzer, debug=False, output_file=None):
        self._analyzer = analyzer
        self._debug = debug
        self._output_file = output_file
        self._output_buffer = []

    def debug_print(self, message):
        if self._debug:
            debug_msg = f"DEBUG: {message}"
            if self._output_file:
                self._output_buffer.append(debug_msg)
            else:
                print(debug_msg)

    def write_output(self):
        if self._output_file and self._output_buffer:
            with open(self._output_file, 'a', encoding='utf-8') as f:
                f.write("\n".join(self._output_buffer))
                f.write("\n")
            self._output_buffer = []

    def print_info(self):
        """
        Печатает (или записывает в файл) всю собранную информацию,
        формируя текст так, как было в исходной версии.
        """
        if self._output_file:
            from rich.console import Console as StringConsole
            str_console = StringConsole(record=True)
            self._print_info_to_console(str_console)
            self._output_buffer.append(str_console.export_text())
            self.write_output()
        else:
            console = Console()
            self._print_info_to_console(console)

    def _print_info_to_console(self, console):
        """
        Восстанавливаем формат вывода, как в исходном PEFile:
        - Пустые строки между разделами
        - [bold green], [bold blue] заголовки
        - Прочие Rich-стили
        """
        # Заголовок
        console.print(f"[bold blue]Анализ файла:[/bold blue] {self._analyzer.filepath}\n")

        # Раздел: Основная информация
        console.print(f"[bold green]Основная информация:[/bold green]")
        machine_text = f"Machine: {hex(self._analyzer.machine)}" if self._analyzer.machine else "Machine: N/A"
        console.print(machine_text)
        console.print(f"Количество секций: {self._analyzer.num_sections}")
        console.print(f"Timestamp: {self._analyzer.timestamp}\n")

        # Раздел: Секции
        console.print(f"[bold green]Секции:[/bold green]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Имя", style="cyan")
        table.add_column("Virtual Size", style="green")
        table.add_column("Virtual Address", style="yellow")
        table.add_column("Raw Size", style="red")
        table.add_column("Raw Offset", style="blue")

        for section in self._analyzer.sections:
            table.add_row(
                section.name,
                hex(section.virtual_size),
                hex(section.virtual_address),
                hex(section.raw_size),
                hex(section.raw_offset)
            )
        console.print(table)

        # Раздел: Машинный код
        console.print("")
        console.print(f"[bold green]Машинный код:[/bold green]")
        for i, section in enumerate(self._analyzer.sections, 1):
            if section.machine_code and section.raw_size > 0:
                mc = section.machine_code
                console.print(f"\nМашинный код #{i} (секция {section.name}):")
                console.print(f"  Виртуальный адрес: {hex(mc['virtual_address'])}")
                console.print(f"  Физический адрес: {hex(mc['physical_address'])}")
                console.print(f"  Размер: {mc['size']} байт")
                console.print(f"  Первые 32 байта:")
                console.print(f"   {mc['first_bytes']}\n")

        # Раздел: Таблица импортов
        imports = self._analyzer.imports
        if imports:
            console.print(f"[bold green]Таблица импортов:[/bold green]")
            for dll, funcs in imports.items():
                console.print(f"\n[yellow]{dll}:[/yellow]")
                console.print(f"  {', '.join(funcs)}")
        console.print("")
