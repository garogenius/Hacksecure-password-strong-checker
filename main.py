import re

class PasswordStrengthChecker:
    def __init__(self, password):
        self.password = password

    def evaluate_strength(self):
        strength_score = 0

        # Criteria for password strength
        length_criteria = len(self.password) >= 8
        uppercase_criteria = bool(re.search(r'[A-Z]', self.password))
        lowercase_criteria = bool(re.search(r'[a-z]', self.password))
        digit_criteria = bool(re.search(r'[0-9]', self.password))
        special_char_criteria = bool(re.search(r'[^A-Za-z0-9]', self.password))

        # Calculate strength score
        if length_criteria:
            strength_score += 1
        if uppercase_criteria:
            strength_score += 1
        if lowercase_criteria:
            strength_score += 1
        if digit_criteria:
            strength_score += 1
        if special_char_criteria:
            strength_score += 1

        # Determine strength level
        if strength_score == 5:
            return "Strong"
        elif strength_score >= 3:
            return "Moderate"
        else:
            return "Weak"

    def get_feedback(self):
        strength = self.evaluate_strength()
        feedback = {
            "Weak": "Your password is weak. Consider making it longer and including uppercase letters, numbers, and special characters.",
            "Moderate": "Your password is moderate. It could be improved by adding more complexity.",
            "Strong": "Your password is strong. Good job!"
        }
        return feedback[strength]

def main():
    print("Password Strength Checker")
    password = input("Enter your password: ")

    checker = PasswordStrengthChecker(password)
    strength = checker.evaluate_strength()
    feedback = checker.get_feedback()

    print(f"Password Strength: {strength}")
    print(f"Feedback: {feedback}")

if __name__ == "__main__":
    main()