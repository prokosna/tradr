package com.tradr.plugin

import androidx.core.content.FileProvider

// The application manifest already declares FileProvider, and one class cannot be two providers.
class TradrFileProvider : FileProvider()
