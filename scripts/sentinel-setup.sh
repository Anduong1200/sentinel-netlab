#!/usr/bin/env bash
# Sentinel NetLab Interactive Setup (TUI)
# A unified wizard to manage the entire lab installation and lifecycle.

set -e

TITLE="Sentinel NetLab Setup"
BACKTITLE="Sentinel NetLab - Advanced WiFi Security Analytics"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
HOST_INSTALL_MIN_KB=2097152
PYTHON_SETUP_MIN_KB=1048576

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

available_kb() {
    local target_path="${1:-/}"
    df -Pk "$target_path" | awk 'NR==2 {print $4}'
}

require_free_space() {
    local target_path="$1"
    local min_kb="$2"
    local action_label="$3"
    local avail_kb mount_point avail_mb need_mb

    avail_kb="$(available_kb "$target_path")"
    mount_point="$(df -P "$target_path" | awk 'NR==2 {print $6}')"
    avail_mb=$(( ${avail_kb:-0} / 1024 ))
    need_mb=$(( min_kb / 1024 ))

    if [ -z "$avail_kb" ] || [ "$avail_kb" -lt "$min_kb" ]; then
        whiptail --title "Low Disk Space" --msgbox "$action_label requires at least ${need_mb} MB free on ${mount_point}.\n\nAvailable: ${avail_mb} MB\n\nSuggested cleanup:\n- sudo apt clean\n- sudo journalctl --vacuum-time=3d\n- remove old Docker images/volumes\n- remove large downloads or PCAP files\n\nThe action was cancelled before it could fail midway." 18 78
        return 1
    fi
}

docker_compose_available() {
    docker compose version >/dev/null 2>&1 || command -v docker-compose >/dev/null 2>&1
}

docker_daemon_ready() {
    docker info >/dev/null 2>&1
}

ensure_lab_prereqs() {
    if ! command -v docker >/dev/null 2>&1; then
        whiptail --title "Docker Missing" --msgbox "Docker is not installed.\n\nRun 'Install Host Dependencies' first, or install Docker manually." 10 68
        return 1
    fi

    if ! docker_compose_available; then
        whiptail --title "Docker Compose Missing" --msgbox "Docker Compose is not installed.\n\nInstall one of these first:\n- sudo apt-get install docker-compose-plugin\n- sudo apt-get install docker-compose\n\nThen retry the Lab action." 12 72
        return 1
    fi

    if ! docker_daemon_ready; then
        whiptail --title "Docker Not Running" --msgbox "Docker daemon is not running or your user cannot access it.\n\nTry:\n- sudo systemctl start docker\n- sudo usermod -aG docker \$USER && newgrp docker" 12 72
        return 1
    fi
}

menu_install_deps() {
    if whiptail --title "$TITLE" --yesno "This will attempt to install base dependencies (Docker, Python, Git, Make) using your system's package manager. Require root privilege (sudo).\n\nContinue?" 12 60; then
        require_free_space "/" "$HOST_INSTALL_MIN_KB" "Installing host dependencies" || return
        clear
        echo "Installing core dependencies..."

        if command -v pacman &> /dev/null; then
            if sudo pacman -Syu --noconfirm && \
               sudo pacman -S --needed --noconfirm python python-pip python-virtualenv docker docker-compose git make base-devel; then
                sudo systemctl enable --now docker || true
                sudo usermod -aG docker "$USER" || true
                whiptail --title "Success" --msgbox "Core dependencies installed successfully!\n\nNOTE: You may need to logout and login again for Docker user-group permissions to apply." 10 60
            else
                whiptail --title "Install Failed" --msgbox "Host dependency installation failed.\n\nCheck the terminal output above for details.\n\nIf disk space is low, free some space first and retry." 10 68
            fi
        elif command -v apt-get &> /dev/null; then
            if sudo apt-get update && \
               sudo apt-get install -y python3 python3-pip python3-venv docker.io docker-compose-plugin git make build-essential; then
                sudo systemctl enable --now docker || true
                sudo usermod -aG docker "$USER" || true
                whiptail --title "Success" --msgbox "Core dependencies installed successfully!\n\nNOTE: You may need to logout and login again for Docker user-group permissions to apply." 10 60
            else
                whiptail --title "Install Failed" --msgbox "Host dependency installation failed.\n\nCheck the terminal output above for details.\n\nYour last run shows the root filesystem was full, so free disk space before retrying." 11 72
            fi
        else
            whiptail --title "Error" --msgbox "Unsupported package manager. Please install dependencies manually." 8 60
            return
        fi
    fi
}

menu_setup_python() {
    require_free_space "/" "$PYTHON_SETUP_MIN_KB" "Setting up the Python environment" || return
    clear
    echo "Setting up Python Virtual Environment..."
    if make -C "$PROJECT_ROOT" install; then
        whiptail --title "Success" --msgbox "Python Virtual Environment (venv) created and dependencies installed successfully." 8 60
    else
         whiptail --title "Error" --msgbox "Failed to setup Python environment. Check the terminal output above for details." 8 60
    fi
}

menu_wifi_drivers() {
    local choice
    choice=$(whiptail --title "$TITLE - WiFi Drivers" --menu "Select your adapter type / target:" 15 60 4 \
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
        local choice
        choice=$(whiptail --title "$TITLE - Lab Environment" --menu "Manage local Lab via Docker Compose:" 15 60 5 \
            "1" "Start Lab (make lab-up)" \
            "2" "Stop Lab (make lab-down)" \
            "3" "Check Status (make lab-status)" \
            "4" "Factory Reset Lab (Wipe DB & Secrets)" \
            "0" "Back to Main Menu" \
            3>&1 1>&2 2>&3)

        case $choice in
            1)
                ensure_lab_prereqs || continue
                clear
                echo "Starting Sentinel NetLab..."
                make -C "$PROJECT_ROOT" lab-up || true
                echo ""
                read -p "Press Enter to continue..."
                ;;
            2)
                ensure_lab_prereqs || continue
                clear
                echo "Stopping Sentinel NetLab..."
                make -C "$PROJECT_ROOT" lab-down || true
                echo ""
                read -p "Press Enter to continue..."
                ;;
            3)
                ensure_lab_prereqs || continue
                clear
                make -C "$PROJECT_ROOT" lab-status || true
                echo ""
                read -p "Press Enter to continue..."
                ;;
            4)
                if whiptail --title "Warning" --yesno "DANGER: This will wipe all lab databases, volumes, and generate fresh secrets.\n\nAre you absolutely sure you want to reset the environment?" 10 60; then
                    ensure_lab_prereqs || continue
                    clear
                    echo "Resetting Sentinel NetLab..."
                    make -C "$PROJECT_ROOT" lab-reset || true
                    echo ""
                    read -p "Press Enter to continue..."
                fi
                ;;
            0|*)
                return
                ;;
        esac
    done
}

main_menu() {
    while true; do
        local choice
        choice=$(whiptail --title "$TITLE" --backtitle "$BACKTITLE" --menu "Main Menu - Choose an action:" 16 60 6 \
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
cd "$PROJECT_ROOT"
main_menu
