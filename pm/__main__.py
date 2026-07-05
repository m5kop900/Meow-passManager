import argparse
import sqlite3

from .manager import PasswordManager

VERSION = "1.0.5"


def build_parser():
    parser = argparse.ArgumentParser(
        prog="pm",
        description="Meow PassManager",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"Meow PassManager {VERSION}",
    )

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("add")
    sub.add_parser("show")
    sub.add_parser("list")
    sub.add_parser("search")
    sub.add_parser("remove")
    sub.add_parser("edit")
    sub.add_parser("copy")
    sub.add_parser("changepassword")
    sub.add_parser("run")

    gen = sub.add_parser("generate")
    gen.add_argument("length", nargs="?", type=int, default=16)

    exp = sub.add_parser("export")
    exp.add_argument("path", nargs="?", default=None)

    imp = sub.add_parser("import")
    imp.add_argument("path")

    return parser


def dispatch(app: PasswordManager, args):
    if args.command is None or args.command == "run":
        app.initialize_secure_session()
        app.run()
        return

    if args.command in ["add", "show", "list", "search", "remove", "edit", "copy", "changepassword"]:
        app.initialize_secure_session()

    match args.command:
        case None | "run":
            app.run()

        case "add":
            app.add()

        case "show":
            app.show_password()

        case "list":
            app.show()

        case "search":
            app.advanced_search()

        case "remove":
            app.removei()

        case "edit":
            app.edit()

        case "copy":
            app.copy_password_to_clipboard()

        case "changepassword":
            app.change_master_password()

        case "generate":
            print(app.random_pass_generator(args.length))

        case "export":
            path = args.path or "vault_export.vault"
            app.export_data(path)

        case "import":
            app.import_data(args.path)


def main():
    parser = build_parser()
    args = parser.parse_args()

    app = PasswordManager()

    try:
        dispatch(app, args)

    except KeyboardInterrupt:
        print("\nBye")

    finally:
        try:
            app.conn.commit()
            app.conn.close()
        except sqlite3.ProgrammingError:
            pass


if __name__ == "__main__":
    main()