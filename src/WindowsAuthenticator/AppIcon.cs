using System.Drawing.Drawing2D;

namespace WindowsAuthenticator;

/// <summary>
/// The app icon drawn in code: a shield with a keyhole inside a countdown ring on a blue gradient, the
/// shapes of Mac Authenticator's icon layers on their 1024-unit canvas.
/// </summary>
internal static class AppIcon
{
    /// <summary>The icon at the given size in pixels.</summary>
    public static Icon Create(int size)
    {
        using var bitmap = new Bitmap(size, size);
        using (var graphics = Graphics.FromImage(bitmap))
        {
            graphics.SmoothingMode = SmoothingMode.AntiAlias;
            graphics.ScaleTransform(size / 1024f, size / 1024f);

            using (var background = RoundedSquare(0, 0, 1024, 224))
            using (var gradient = new LinearGradientBrush(new Point(0, 0), new Point(0, 1024),
                                                          Color.FromArgb(0x4F, 0x46, 0xE5), Color.FromArgb(0x0E, 0xA5, 0xE9)))
            {
                graphics.FillPath(gradient, background);
            }

            // The ring: a faint full track and three quarters clockwise from the top.
            using (var track = new Pen(Color.FromArgb(77, Color.White), 72))
            {
                graphics.DrawEllipse(track, 140, 140, 744, 744);
            }
            using (var ring = new Pen(Color.White, 72) { StartCap = LineCap.Round, EndCap = LineCap.Round })
            {
                graphics.DrawArc(ring, 140, 140, 744, 744, -90, 270);
            }

            using (var shield = new GraphicsPath())
            {
                shield.AddBezier(325.6f, 334.3f, 381.9f, 303.6f, 444.1f, 284.2f, 512f, 275.9f);
                shield.AddBezier(512f, 275.9f, 579.9f, 284.2f, 642.1f, 303.6f, 698.4f, 334.3f);
                shield.AddBezier(698.4f, 334.3f, 698.4f, 551.8f, 621.4f, 691f, 512f, 753.1f);
                shield.AddBezier(512f, 753.1f, 402.6f, 691f, 325.6f, 551.8f, 325.6f, 334.3f);
                shield.CloseFigure();
                graphics.FillPath(Brushes.White, shield);
            }

            using (var keyhole = new SolidBrush(Color.FromArgb(0x43, 0x38, 0xCA)))
            {
                graphics.FillEllipse(keyhole, 512f - 57.2f, 467.3f - 57.2f, 114.4f, 114.4f);
                graphics.FillPolygon(keyhole, new PointF[]
                {
                    new(484.7f, 467.3f), new(467.3f, 626.3f), new(556.7f, 626.3f), new(539.3f, 467.3f),
                });
            }
        }
        var handle = bitmap.GetHicon();
        try
        {
            using var borrowed = Icon.FromHandle(handle);
            return (Icon)borrowed.Clone();
        }
        finally
        {
            NativeMethods.DestroyIcon(handle);
        }
    }

    private static GraphicsPath RoundedSquare(float x, float y, float side, float radius)
    {
        var path = new GraphicsPath();
        var d = radius * 2;
        path.AddArc(x, y, d, d, 180, 90);
        path.AddArc(x + side - d, y, d, d, 270, 90);
        path.AddArc(x + side - d, y + side - d, d, d, 0, 90);
        path.AddArc(x, y + side - d, d, d, 90, 90);
        path.CloseFigure();
        return path;
    }
}
