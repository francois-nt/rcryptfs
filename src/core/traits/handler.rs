use std::{
    borrow::{Borrow, BorrowMut},
    ops::{Deref, DerefMut},
};

pub trait HandlerTarget {
    type Stored: Borrow<Self> + BorrowMut<Self>;
}

impl<T: Sized> HandlerTarget for T {
    type Stored = T;
}

pub struct Handler<T: HandlerTarget + ?Sized>(T::Stored);

impl<T: HandlerTarget + ?Sized> Handler<T> {
    pub fn from_repr(value: T::Stored) -> Self {
        Self(value)
    }

    /// Returns the stored representation of the handle.
    pub fn into_repr(self) -> T::Stored {
        self.0
    }
}

impl<T: HandlerTarget + ?Sized> AsRef<T::Stored> for Handler<T> {
    fn as_ref(&self) -> &T::Stored {
        &self.0
    }
}

impl<T: HandlerTarget + ?Sized> AsMut<T::Stored> for Handler<T> {
    fn as_mut(&mut self) -> &mut T::Stored {
        &mut self.0
    }
}

impl<T: HandlerTarget<Stored = T>> Handler<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }
}

impl<T: HandlerTarget + ?Sized> Deref for Handler<T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.0.borrow()
    }
}

impl<T: HandlerTarget + ?Sized> DerefMut for Handler<T> {
    fn deref_mut(&mut self) -> &mut T {
        self.0.borrow_mut()
    }
}

#[macro_export]
macro_rules! impl_dyn_handler_target {
    ($($tr:path),+ $(,)?) => {
        $(
            impl<'a> HandlerTarget for dyn $tr + 'a {
                type Stored = Box<dyn $tr + 'a>;
            }

            impl<'a, T> From<Handler<T>> for Handler<dyn $tr + 'a>
            where
                T: $tr + 'a,
            {
                fn from(value: Handler<T>) -> Self {
                    Handler::from_repr(Box::new(value.into_repr()) as Box<dyn $tr + 'a>)
                }
            }

        )+
    };
}
