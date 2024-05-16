use crate::garble::{GarbledCircuit, GarbledGate, GarbledWire, GarbledWireValue, OutputTable};
use std::io::{Write, Read};


pub trait SerializableWith : Sized {
    type AssociatedSerializeData = ();
    type AssociatedDeserializeData = ();
    fn serialize_into_with(&self, writer: &mut impl Write, data: Self::AssociatedSerializeData) -> std::io::Result<()>;
    fn deserialize_from_with(reader: &mut impl Read, data: Self::AssociatedDeserializeData) -> std::io::Result<Self>;
}
pub trait Serializable : Sized {
    fn serialize_into(&self, writer: &mut impl Write) -> std::io::Result<()>;
    fn deserialize_from(reader: &mut impl Read) -> std::io::Result<Self>;
}

impl<T> Serializable for T where
    T : SerializableWith<AssociatedSerializeData = (), AssociatedDeserializeData = ()> {
    fn serialize_into(&self, writer: &mut impl Write) -> std::io::Result<()> {
        self.serialize_into_with(writer, ())
    }
    
    fn deserialize_from(reader: &mut impl Read) -> std::io::Result<Self> {
        Self::deserialize_from_with(reader, ())
    }
}

impl<const N: usize> SerializableWith for [u8; N] {
    fn serialize_into_with(&self, writer: &mut impl Write, data: ()) -> std::io::Result<()> {
        writer.write_all(self)
    }
    
    fn deserialize_from_with(reader: &mut impl Read, data: ()) -> std::io::Result<Self> {
        let mut res = [0u8; N];
        reader.read_exact(&mut res)?;
        Ok(res)
    }
}

impl SerializableWith for u64 {
    fn serialize_into_with(&self, writer: &mut impl Write, data: ()) -> std::io::Result<()> {
        let buf = self.to_le_bytes();
        assert_eq!(buf.len(), 8);
        buf.serialize_into(writer)
    }
    
    fn deserialize_from_with(reader: &mut impl Read, data: ()) -> std::io::Result<Self> {
        let buf: [u8; 8] = <[u8; 8]>::deserialize_from(reader)?;
        Ok(u64::from_le_bytes(buf))
    }
}

impl SerializableWith for usize {
    fn serialize_into_with(&self, writer: &mut impl Write, data: ()) -> std::io::Result<()> {
        (*self as u64).serialize_into(writer)
    }

    fn deserialize_from_with(reader: &mut impl Read, data: ()) -> std::io::Result<Self> {
        let r = u64::deserialize_from(reader)?;
        Ok(r as usize)
    }
}

impl<T, const N: usize> SerializableWith for [T; N] where T: Serializable {
    fn serialize_into_with(&self, writer: &mut impl Write, data: ()) -> std::io::Result<()> {
        for i in self.iter() {
            i.serialize_into(writer)?;
        }
        Ok(())
    }

    fn deserialize_from_with(reader: &mut impl Read, data: ()) -> std::io::Result<Self> {
        let res = core::array::try_from_fn(|_| T::deserialize_from(reader))?;
        Ok(res)
    }
}

impl<T> SerializableWith for Vec<T> where T: Serializable {
    fn serialize_into_with(&self, writer: &mut impl Write, data: ()) -> std::io::Result<()> {
        self.len().serialize_into(writer)?;
        for i in self.iter() {
            i.serialize_into(writer)?;
        }
        Ok(())
    }

    fn deserialize_from_with(reader: &mut impl Read, _: ()) -> std::io::Result<Self> {
        let len = usize::deserialize_from(reader)?;
        let mut r = Vec::with_capacity(len);
        for _ in 0..len {
            let x = T::deserialize_from(reader)?;
            r.push(x);
        }
        Ok(r)
    }
}

impl<T, S> SerializableWith for (T,S) where T: SerializableWith, S: SerializableWith {
    type AssociatedSerializeData = (T::AssociatedSerializeData, S::AssociatedSerializeData);
    type AssociatedDeserializeData = (T::AssociatedDeserializeData, S::AssociatedDeserializeData);

    fn serialize_into_with(&self, writer: &mut impl Write, data: Self::AssociatedSerializeData) -> std::io::Result<()> {
        self.0.serialize_into_with(writer, data.0)?;
        self.1.serialize_into_with(writer, data.1)
    }

    fn deserialize_from_with(reader: &mut impl Read, data: Self::AssociatedDeserializeData) -> std::io::Result<Self> {
        let a = T::deserialize_from_with(reader, data.0)?;
        let b = S::deserialize_from_with(reader, data.1)?;
        Ok((a,b))
    }
}

impl Serializable for GarbledWire {
    fn serialize_into(&self, writer: &mut impl std::io::prelude::Write) -> std::io::Result<()> {
        self.0.serialize_into(writer)?;
        self.1.serialize_into(writer)
    }

    fn deserialize_from(reader: &mut impl std::io::prelude::Read) -> std::io::Result<Self> {
        let v0 = GarbledWireValue::deserialize_from(reader)?;
        let v1 = GarbledWireValue::deserialize_from(reader)?;
        Ok(GarbledWire(v0,v1))
    }
}

impl Serializable for GarbledGate {
    fn serialize_into(&self, writer: &mut impl Write) -> std::io::Result<()> {
        self.table.serialize_into(writer)
    }

    fn deserialize_from(reader: &mut impl Read) -> std::io::Result<Self> {
        let table = Serializable::deserialize_from(reader)?;
        Ok(Self {table})
    }
}

impl Serializable for OutputTable {
    fn serialize_into(&self, writer: &mut impl Write) -> std::io::Result<()> {
        self.table.serialize_into(writer)
    }

    fn deserialize_from(reader: &mut impl Read) -> std::io::Result<Self> {
        let table = Serializable::deserialize_from(reader)?;
        Ok(Self {table})
    }
}

impl<'a> Serializable for GarbledCircuit<'a> {
    fn serialize_into(&self, writer: &mut impl Write) -> std::io::Result<()> {
        todo!()
    }

    fn deserialize_from(reader: &mut impl Read) -> std::io::Result<Self> {
        todo!()
    }
}