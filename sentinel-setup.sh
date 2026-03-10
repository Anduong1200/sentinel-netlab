#!/usr/bin/env bash
# Sentinel NetLab Interactive Setup (TUI)
# A unified wizard to manage the entire lab installation and lifecycle.

set -e

TITLE="Sentinel NetLab Setup"
BACKTITLE="Sentinel NetLab - Advanced WiFi Security Analytics"

# Function to ensure we have the tool needed to draw the UI
check_ui_deps() {
    if ! command -v whiptail &> /dev/null; then
        echo "Whiptail is missing. Attempting to install it..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y whiptail
        elif command -v pacman &> /dev/null; then
            sudo pacman -Sy --noconfirm whiptail
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y newt
        else
            echo "ERROR: Could not auto-install whiptail. Please install it manually to use this setup wizard."
            exit 1
        fi
    fi
}

menu_install_deps() {
    if whiptail --title "$TITLE" --yesno "This will attempt to install base dependencies (Docker, Python, Git, Make) using your system's package manager. Require root privilege (sudo).\n\nContinue?" 12 60; then
        clear
        echo "Installing core dependencies..."
        if command -v pacman &> /dev/null; then
            sudo pacman -Syu --noconfirm
            sudo pacman -S --needed --noconfirm python python-pip python-virtualenv docker docker-compose git make base-devel
            sudo systemctl enable --now docker
            sudo usermod -aG docker "$USER"
        elif command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y python3 python3-pip python3-venv docker.io docker-compose git make build-essential
            sudo systemctl enable --now docker
            sudo usermod -aG docker "$USER"
        else
            whiptail --title "Error" --msgbox "Unsupported package manager. Please install dependencies manually." 8 60
            return
        fi
        whiptail --title "Success" --msgbox "Core dependencies installed successfully!\n\nNOTE: You may need to logout and login again for Docker user-group permissions to apply." 10 60
    fi
}

menu_setup_python() {
    clear
    echo "Setting up Python Virtual Environment..."
    if make install; then
        whiptail --title "Success" --msgbox "Python Virtual Environment (venv) created and dependencies installed successfully." 8 60
    else
         whiptail --title "Error" --msgbox "Failed to setup Python environment. Check the terminal output above for details." 8 60
    fi
}

menu_wifi_drivers() {
    local choice=$(whiptail --title "$TITLE - WiFi Drivers" --menu "Select your adapter type / target:" 15 60 4 \
        "1" "ALFA AWUS036AXML (Arch Linux Auto-Install)" \
        "2" "View Universal Linux Driver Guide" \
        "0" "Back" \
        3>&1 1>&2 2>&3)
        
    case $choice in
        1)
            clear
            if [ -f "ops/scripts/install_awus036axml_arch.sh" ]; then
                bash ops/scripts/install_awus036axml_arch.sh || true
                echo ""
                read -p "Press Enter to return to menu..."
            else
                whiptail --title "Error" --msgbox "Script ops/scripts/install_awus036axml_arch.sh not found!" 8 60
            fi
            ;;
        2)
            if command -v less &> /dev/null && [ -f "docs/reference/wifi_drivers.md" ]; then
                less docs/reference/wifi_drivers.md
            else
                whiptail --title "Info" --msgbox "Please read docs/reference/wifi_drivers.md directly." 8 60
            fi
            ;;
    esac
}

menu_lab_manage() {
    while true; do
        local choice=$(whiptail --title "$TITLE - Lab Environment" --menu "Manage local Lab via Docker Compose:" 15 60 5 \
            "1" "Start Lab (make lab-up)" \
            "2" "Stop Lab (make lab-down)" \
            "3" "Check Status (make lab-status)" \
            "4" "Factory Reset Lab (Wipe DB & Secrets)" \
            "0" "Back to Main Menu" \
            3>&1 1>&2 2>&3)
            
        case $choice in
            1)
                clear
                echo "Starting Sentinel NetLab..."
                make lab-up || true
                echo ""
                read -p "Press Enter to continue..."
                ;;
            2)
                clear
                echo "Stopping Sentinel NetLab..."
                make lab-down || true
                echo ""
                read -p "Press Enter to continue..."
                ;;
            3)
                clear
                make lab-status || true
                echo ""
                read -p "Press Enter to continue..."
                ;;
            4)
                if whiptail --title "Warning" --yesno "DANGER: This will wipe all lab databases, volumes, and generate fresh secrets.\n\nAre you absolutely sure you want to reset the environment?" 10 60; then
                    clear
                    echo "Resetting Sentinel NetLab..."
                    make lab-reset || true
                    echo ""
                    read -p "Press Enter to continue..."
                fi
                ;;
            0|*) return ;;
        esac
    done
}

main_menu() {
    while true; do
        local choice=$(whiptail --title "$TITLE" --backtitle "$BACKTITLE" --menu "Main Menu - Choose an action:" 16 60 6 \
            "1" "Install Host Dependencies (Arch/Ubuntu)" \
            "2" "Setup Python Environment (venv)" \
            "3" "Install/Configure WiFi Drivers" \
            "4" "Manage Lab Runtime (Start/Stop/Reset)" \
            "0" "Exit" \
            3>&1 1>&2 2>&3)
            
        case $choice in
            1) menu_install_deps ;;
            2) menu_setup_python ;;
            3) menu_wifi_drivers ;;
            4) menu_lab_manage ;;
            0|*) 
                clear
                echo "Exiting Sentinel Setup. Run 'make help' inside the project for manual developer commands."
                exit 0 
                ;;
        esac
    done
}

# Entry Point
check_ui_deps
cd "$(dirname "$0")" # Ensure we are in project root
main_menu
