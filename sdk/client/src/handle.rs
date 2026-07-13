#[cfg(target_arch = "wasm32")]
type Inner<T> = std::rc::Rc<T>;

#[cfg(not(target_arch = "wasm32"))]
type Inner<T> = std::sync::Arc<T>;

/// Shared ownership wrapper
pub struct Handle<T: ?Sized>(Inner<T>);

impl<T: ?Sized> Clone for Handle<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: ?Sized> Handle<T> {
    pub fn from_box(boxed: Box<T>) -> Self {
        Self(Inner::from(boxed))
    }
}

impl<T: ?Sized> std::ops::Deref for Handle<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: ?Sized> AsRef<T> for Handle<T> {
    fn as_ref(&self) -> &T {
        self
    }
}

impl<T: ?Sized> From<Box<T>> for Handle<T> {
    fn from(boxed: Box<T>) -> Self {
        Self::from_box(boxed)
    }
}
