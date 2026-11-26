namespace WindowsAuthenticator;

/// <summary>The app icon, Resources/AppIcon.ico, embedded in the assembly as AppIcon.ico.</summary>
internal static class AppIcon
{
    /// <summary>The image of the icon closest to the given size.</summary>
    public static Icon Load(Size size)
    {
        using var stream = typeof(AppIcon).Assembly.GetManifestResourceStream("AppIcon.ico")
                           ?? throw new InvalidOperationException("The app icon is missing from the assembly.");
        return new Icon(stream, size);
    }

    /// <summary>The icon of the given size with the system's warning sign over its lower right quarter.</summary>
    public static Icon LoadWithWarning(Size size)
    {
        using var icon = Load(size);
        using var bitmap = new Bitmap(size.Width, size.Height);
        using (var graphics = Graphics.FromImage(bitmap))
        using (var warning = new Icon(SystemIcons.Warning, size))
        {
            graphics.DrawIcon(icon, new Rectangle(Point.Empty, size));
            var corner = new Size((size.Width * 3 + 4) / 5, (size.Height * 3 + 4) / 5);
            graphics.DrawIcon(warning, new Rectangle(new Point(size.Width - corner.Width, size.Height - corner.Height), corner));
        }
        return FromBitmap(bitmap);
    }

    /// <summary>
    /// The icon of the given size with a badge over its lower right quarter: a blue dot with three white dots while
    /// a vault call runs, or a green dot with a white check mark after a copy.
    /// </summary>
    public static Icon LoadWithBadge(Size size, bool busy)
    {
        using var icon = Load(size);
        using var bitmap = new Bitmap(size.Width, size.Height);
        using (var graphics = Graphics.FromImage(bitmap))
        using (var fill = new SolidBrush(busy ? Color.RoyalBlue : Color.ForestGreen))
        using (var white = new SolidBrush(Color.White))
        using (var pen = new Pen(Color.White, Math.Max(1f, size.Width / 12f)))
        {
            graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            graphics.DrawIcon(icon, new Rectangle(Point.Empty, size));
            var side = (size.Width * 3 + 4) / 5;
            var badge = new RectangleF(size.Width - side, size.Height - side, side, side);
            graphics.FillEllipse(fill, badge);
            if (busy)
            {
                var dot = side / 6f;
                for (var i = 0; i < 3; i++)
                {
                    graphics.FillEllipse(white, badge.X + side * (0.2f + 0.3f * i) - dot / 2, badge.Y + side / 2f - dot / 2, dot, dot);
                }
            }
            else
            {
                graphics.DrawLines(pen, [
                    new PointF(badge.X + side * 0.25f, badge.Y + side * 0.5f),
                    new PointF(badge.X + side * 0.45f, badge.Y + side * 0.7f),
                    new PointF(badge.X + side * 0.75f, badge.Y + side * 0.3f),
                ]);
            }
        }
        return FromBitmap(bitmap);
    }

    /// <summary>
    /// An icon of one 32-bit image, written as an .ico file in memory with a DIB and an empty AND mask, so the
    /// icon owns its data.
    /// </summary>
    private static Icon FromBitmap(Bitmap bitmap)
    {
        var width = bitmap.Width;
        var height = bitmap.Height;
        var maskRow = (width + 31) / 32 * 4;
        var imageSize = 40 + width * height * 4 + maskRow * height;
        using var ico = new MemoryStream();
        using (var writer = new BinaryWriter(ico, System.Text.Encoding.ASCII, leaveOpen: true))
        {
            // ICONDIR: reserved, type 1 (icon), one image.
            writer.Write((ushort)0);
            writer.Write((ushort)1);
            writer.Write((ushort)1);
            // ICONDIRENTRY: width, height, no palette, reserved, planes, bit count, size, offset.
            writer.Write((byte)width);
            writer.Write((byte)height);
            writer.Write((byte)0);
            writer.Write((byte)0);
            writer.Write((ushort)1);
            writer.Write((ushort)32);
            writer.Write(imageSize);
            writer.Write(6 + 16);
            // BITMAPINFOHEADER: the height counts the image and the mask.
            writer.Write(40);
            writer.Write(width);
            writer.Write(height * 2);
            writer.Write((ushort)1);
            writer.Write((ushort)32);
            writer.Write(0);
            writer.Write(width * height * 4 + maskRow * height);
            writer.Write(0);
            writer.Write(0);
            writer.Write(0);
            writer.Write(0);
            // The pixels as BGRA, bottom row first, then the AND mask, all transparent bits clear.
            for (var y = height - 1; y >= 0; y--)
            {
                for (var x = 0; x < width; x++)
                {
                    var pixel = bitmap.GetPixel(x, y);
                    writer.Write(pixel.B);
                    writer.Write(pixel.G);
                    writer.Write(pixel.R);
                    writer.Write(pixel.A);
                }
            }
            writer.Write(new byte[maskRow * height]);
        }
        ico.Position = 0;
        return new Icon(ico);
    }
}
