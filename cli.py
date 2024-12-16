import click
from rich.console import Console
from analyzer import PEAnalyzer
from reporter import PEReporter

console = Console()

@click.command()
@click.argument('filepath', type=click.Path(exists=True))
@click.option('--debug', is_flag=True, help='Включить отладочный вывод')
@click.option('--output', '-o', type=click.Path(), help='Файл для сохранения результатов')
def main(filepath, debug, output):
    """Декомпилятор EXE файлов, разбитый на анализатор и репортёр."""
    try:
        analyzer = PEAnalyzer(filepath)
        analyzer.analyze()

        reporter = PEReporter(analyzer, debug=debug, output_file=output)
        reporter.print_info()
    except Exception as e:
        error_msg = f"[bold red]Ошибка:[/bold red] {str(e)}"
        if output:
            with open(output, 'a', encoding='utf-8') as f:
                f.write(f"\nОШИБКА: {str(e)}\n")
        else:
            console.print(error_msg)

def run_cli():
    main()

if __name__ == '__main__':
    run_cli()
