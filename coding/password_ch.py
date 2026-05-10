#!/usr/bin/env python3
"""
Password Strength Analyzer
Checks how strong your password is.
"""
 
import re
import sys
 
 
def check_password(password):
    score = 0
    feedback = []
 
    # --- Length ---
    length = len(password)
    if length >= 16:
        score += 3
        feedback.append("✅ Long password (16+ chars) — great!")
    elif length >= 12:
        score += 2
        feedback.append("✅ Good length (12+ chars)")
    elif length >= 8:
        score += 1
        feedback.append("⚠️  Okay length (8+ chars) — longer is better")
    else:
        feedback.append("❌ Too short — use at least 8 characters")
 
    # --- Uppercase letters ---
    if re.search(r'[A-Z]', password):
        score += 1
        feedback.append("✅ Has uppercase letters")
    else:
        feedback.append("❌ Add uppercase letters (A-Z)")
 
    # --- Lowercase letters ---
    if re.search(r'[a-z]', password):
        score += 1
        feedback.append("✅ Has lowercase letters")
    else:
        feedback.append("❌ Add lowercase letters (a-z)")
 
    # --- Numbers ---
    if re.search(r'\d', password):
        score += 1
        feedback.append("✅ Has numbers")
    else:
        feedback.append("❌ Add numbers (0-9)")
 
    # --- Special characters ---
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?`~]', password):
        score += 2
        feedback.append("✅ Has special characters (!@#$ etc.)")
    else:
        feedback.append("❌ Add special characters (!@#$ etc.)")
 
    # --- Common weak passwords ---
    common = [
        "password", "123456", "qwerty", "abc123", "letmein",
        "welcome", "monkey", "dragon", "master", "password1"
    ]
    if password.lower() in common:
        score = 0
        feedback.append("🚨 This is a VERY common password — change it!")
 
    # --- Repeated characters ---
    if re.search(r'(.)\1{2,}', password):
        score -= 1
        feedback.append("⚠️  Avoid repeating characters (aaa, 111)")
 
    # --- Rating ---
    score = max(0, score)  # no negative scores
 
    if score <= 2:
        rating = "🔴 WEAK"
    elif score <= 4:
        rating = "🟠 FAIR"
    elif score <= 6:
        rating = "🟡 GOOD"
    else:
        rating = "🟢 STRONG"
 
    return rating, score, feedback
 
 
def main():
    print("=" * 45)
    print("     🔐 Password Strength Analyzer")
    print("=" * 45)
 
    # Accept password from command line OR ask for it
    if len(sys.argv) > 1:
        password = sys.argv[1]
        print(f"\nChecking password: {'*' * len(password)}")
    else:
        password = input("\nEnter your password: ")
 
    if not password:
        print("❌ No password entered. Exiting.")
        sys.exit(1)
 
    rating, score, feedback = check_password(password)
 
    print(f"\n📊 Score : {score} / 8")
    print(f"📈 Rating: {rating}")
    print("\n📋 Details:")
    for item in feedback:
        print(f"   {item}")
 
    print("\n" + "=" * 45)
 
    # Tips
    if "WEAK" in rating or "FAIR" in rating:
        print("\n💡 Tips for a stronger password:")
        print("   • Use 12+ characters")
        print("   • Mix UPPER and lower case")
        print("   • Add numbers and symbols")
        print("   • Avoid common words")
        print("   • Try a passphrase: 'Dog$RunsFast99'")
        print()
 
 
if __name__ == "__main__":
    main()