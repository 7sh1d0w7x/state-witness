# state-witness — demo terminal, pe paleta brandului.
# Vechiul tape folosea tema "Dracula" (mov) cu MarginFill #0b1120 (albastru) —
# off-brand. Acum: tema e definită inline, cu valorile din portfolio/site/style.css.
Output assets/demo.gif

Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 15
Set Width 1000
Set Height 420
Set Padding 20
Set Margin 10
Set MarginFill "#0a0c0b"
Set WindowBar Rings
Set BorderRadius 8
Set Theme { "name": "state-witness", "black": "#0a0c0b", "red": "#ff6b6b", "green": "#5ce08a", "yellow": "#ffb454", "blue": "#4fd8d2", "magenta": "#8b978f", "cyan": "#02C1BA", "white": "#e6ece7", "brightBlack": "#5b665f", "brightRed": "#ff6b6b", "brightGreen": "#5ce08a", "brightYellow": "#ffb454", "brightBlue": "#4fd8d2", "brightMagenta": "#8b978f", "brightCyan": "#02C1BA", "brightWhite": "#ffffff", "background": "#0a0c0b", "foreground": "#e6ece7", "selection": "#1d2421", "cursor": "#02C1BA" }

# output-ul text: ce e pe host, cu proveniență
Set TypingSpeed 0ms
Type "cat assets/demo-output.txt"
Sleep 200ms
Enter
Sleep 3200ms

# și forma mașină: JSON, pentru CI
Type "clear"
Enter
Sleep 300ms
Type "cat assets/demo-output.json"
Sleep 200ms
Enter
Sleep 3600ms
