namespace microCut.Forms;

/// <summary>First-launch modal: shows the legal disclaimer and requires explicit consent.</summary>
public sealed class DisclaimerForm : Form
{
    public const string DisclaimerText =
        "This tool is intended for educational purposes and authorized network administration " +
        "(e.g., testing your own home network) only. Unauthorized interception or disruption of " +
        "network traffic is illegal under laws such as the Computer Fraud and Abuse Act (CFAA) " +
        "and equivalent statutes in other jurisdictions. The developer assumes no liability for misuse.";

    public DisclaimerForm()
    {
        Text = "microCut — Legal & Ethical Disclaimer";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterParent;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        ClientSize = new Size(600, 340);
        Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);

        var heading = new Label
        {
            Dock = DockStyle.Top,
            AutoSize = false,
            Height = 46,
            Padding = new Padding(14, 10, 14, 0),
            Text = "Read this carefully before using microCut.",
            Font = new Font(Font, FontStyle.Bold)
        };

        var body = new Label
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(14, 6, 14, 6),
            Text = DisclaimerText,
            AutoEllipsis = false
        };

        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            AutoSize = true,
            FlowDirection = FlowDirection.RightToLeft,
            Padding = new Padding(10, 6, 10, 8)
        };

        var acceptButton = new Button
        {
            Text = "I Agree — Continue",
            Enabled = false,
            DialogResult = DialogResult.OK,
            Width = 150,
            Height = 32
        };
        var exitButton = new Button
        {
            Text = "Exit",
            DialogResult = DialogResult.Cancel,
            Width = 90,
            Height = 32
        };

        var consentCheck = new CheckBox
        {
            Dock = DockStyle.Bottom,
            Padding = new Padding(10, 0, 10, 0),
            Height = 36,
            Text = "I confirm I have permission to manage this network"
        };
        consentCheck.CheckedChanged += (_, _) => acceptButton.Enabled = consentCheck.Checked;

        buttons.Controls.Add(acceptButton);
        buttons.Controls.Add(exitButton);

        Controls.Add(body);
        Controls.Add(heading);
        Controls.Add(consentCheck);
        Controls.Add(buttons);

        AcceptButton = acceptButton;
        CancelButton = exitButton;
    }
}
