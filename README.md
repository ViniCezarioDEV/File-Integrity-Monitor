<div align="center">
    <h1>File Integrity Monitor (FIM)</h1>
</div>

<div align="center">
    <h3>How it works?</h3>
</div>

- Establishing a baseline for files, including details such as:
    - File name
    - Permissions
    - Baseline creation timestamps
    - File creation timestamps
    - File Hash value
    - File Owner and Group

- Monitoring changes
    - Performing continuously or periodically scans the designated files
    - Detect if the hash value match with the baseline hash
    - Detect if some file has been deleted or created and more

- Generate alerts.
    - If any discrepancies are found (a different hash value, a new file, or a deleted file), the FIM system generates an alert
    - This alert notifies security personnel of suspicious activity, providing details about the specific file and the nature of the change
    - Generate local logs

<div align="center">
    <h3>Why does this matter?</h3>
    Based on the CIA triad (Confidentiality, Integrity, and Availability).<br>
    <img src="https://www.cobalt.io/hs-fs/hubfs/CIA%20Triad%20Graphic-png.png?width=367&height=350&name=CIA%20Triad%20Graphic-png.png" width="230px"><br>
    To keep integrity of all our files, this system detect if some change was performed with the file such as: if a new file was created or deleted, if the content has modified and if permissions has changed.
</div>

<div align="center">
    <h3>How to use the code?</h3>
    ⚠️Firstly, note that the code is for Linux!⚠️
</div><br>

- In "<i>main.py</i>", you must put the path of the directory you want to monitor
- Run the code periodically, or automate the execution
- Check the "<i>fim_system.log</i>" file to see if any log entries were recorded
    - If any entry has been recorded, take appropriate action.
    - If no entries were recorded, <strong>congratulations!</strong> You're ensuring the <strong>integrity</strong> of your data. But always keep monitoring🕵🏻.