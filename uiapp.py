import streamlit as st
import subprocess
import json
import os

def run_nuclei_scan(target_url, severity="critical,high"):
    # 1. INISIALISASI VARIABEL
    # Definisikan nama file output sementara
    output_file = "nuclei_results.jsonl" 
    
    # Inisialisasi list untuk menampung hasil scan (untuk mencegah NameError: name 'results' is not defined)
    results = [] 
    
    # 2. DEFINISI PERINTAH (COMMAND)
    # Perintah Nuclei yang akan dijalankan. 'output_file' harus sudah didefinisikan di atas.
    command = [
        "nuclei",
        "-u", target_url,
        "-severity", severity,
        "-jsonl",
        "-o", output_file
    ]

    # Baris ini sekarang aman karena 'command' sudah didefinisikan
    print(f"Menjalankan perintah: {' '.join(command)}") 
    
    # 3. EKSEKUSI DAN PENANGANAN ERROR
    try:
        # Jalankan perintah Nuclei. check=True akan memunculkan CalledProcessError jika Nuclei gagal.
        # capture_output=True menangkap output stdout/stderr (untuk debug, jika perlu)
        subprocess.run(command, check=True, capture_output=True, text=True, encoding='utf-8', errors='ignore')

        # Buka dan baca file JSONL yang dihasilkan oleh Nuclei
        with open(output_file, 'r') as f:
            for line in f:
                try:
                    results.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    print(f"Error decoding JSON: {line.strip()}")
        
        # Hapus file output sementara setelah selesai dibaca
        os.remove(output_file)
        
    except subprocess.CalledProcessError as e:
        # Ditangkap jika Nuclei dijalankan, tetapi gagal (misalnya error sintaks)
        print(f"Error saat menjalankan Nuclei (CalledProcessError): {e.stderr}")
        return [] 
        
    except FileNotFoundError:
        # Ditangkap jika 'nuclei' tidak ditemukan (belum terinstal atau tidak ada di PATH)
        print("Error: Nuclei tidak ditemukan (FileNotFoundError). Pastikan sudah terinstal dan ada di PATH.")
        return []
    
    except Exception as e:
        # Menangkap error umum lainnya
        print(f"Terjadi error tak terduga: {e}")
        return []

    # 4. RETURN HASIL
    # Mengembalikan list hasil scan (bisa kosong jika tidak ditemukan kerentanan)
    return results

# --- UI Application ---
st.title("🛡️ Nuclei Vulnerability Scanner (Python UI)")

# Input Target URL
target_url = st.text_input("Masukkan Target URL (misalnya: https://contoh.com)", "https://example.com")

# Pilihan Severity
severity_options = st.multiselect(
    "Pilih Tingkat Keparahan yang Akan Dipindai",
    ["info", "low", "medium", "high", "critical"],
    default=["critical", "high"]
)
selected_severity = ",".join(severity_options)

# Tombol Mulai Scan
if st.button("Mulai Scan Nuclei"):
    if not target_url:
        st.error("Masukkan URL target terlebih dahulu.")
    else:
        with st.spinner('Scanning... Ini mungkin memakan waktu beberapa menit ⏳'):
            # Jalankan scan
            results = run_nuclei_scan(target_url, selected_severity)

        if results:
            st.success(f"Scan Selesai! Ditemukan **{len(results)}** hasil.")
            
            # Konversi hasil menjadi format tabel yang mudah dibaca oleh Streamlit
            processed_results = []
            for item in results:
                processed_results.append({
                    "Severity": item.get('info', {}).get('severity', 'N/A').capitalize(),
                    "Name": item.get('info', {}).get('name', 'N/A'),
                    "Matched URL": item.get('host', 'N/A'),
                    "Template ID": item.get('template-id', 'N/A'),
                    "Description": item.get('info', {}).get('description', 'No description')[:100] + "..." # Ambil 100 karakter pertama
                })
            
            # Tampilkan hasil dalam bentuk tabel interaktif
            st.dataframe(processed_results, use_container_width=True)

        else:
            st.info("Scan Selesai. Tidak ditemukan kerentanan berdasarkan kriteria yang dipilih.")