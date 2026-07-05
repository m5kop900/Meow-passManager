from colorama import *
init(autoreset=True)

class InputValidator:
    @staticmethod
    def get(prompt, allow_exit=False, allow_neg=True, max_value=None, min_value=None, number=False, allow_empty=False):
        while True:
            user_input = input(prompt)

            if allow_exit and user_input.lower() == "/q":
                return "/q"

            if not allow_empty and user_input.strip() == "":
                print(Fore.YELLOW + "متن نمی‌تواند خالی باشد" + Style.RESET_ALL)
                continue

            if number:
                try:
                    num = int(user_input)
                except ValueError:
                    print(Fore.YELLOW + "عدد وارد کن" + Style.RESET_ALL)
                    continue

                if not allow_neg and num < 0:
                    print(Fore.YELLOW + "عدد نمی‌تواند منفی باشد" + Style.RESET_ALL)
                    continue

                if max_value is not None and num > max_value:
                    print(Fore.YELLOW + f"عدد نمی‌تواند بیشتر از {max_value} باشد" + Style.RESET_ALL)
                    continue

                if min_value is not None and num < min_value:
                    print(Fore.YELLOW + f"عدد نمی‌تواند کمتر از {min_value} باشد" + Style.RESET_ALL)
                    continue

                return num

            else:
                return user_input