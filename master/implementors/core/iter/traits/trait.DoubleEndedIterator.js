(function() {var implementors = {};
implementors["arrayvec"] = ["impl&lt;A:&nbsp;<a class=\"trait\" href=\"arrayvec/trait.Array.html\" title=\"trait arrayvec::Array\">Array</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/trait.DoubleEndedIterator.html\" title=\"trait core::iter::traits::DoubleEndedIterator\">DoubleEndedIterator</a> for <a class=\"struct\" href=\"arrayvec/struct.IntoIter.html\" title=\"struct arrayvec::IntoIter\">IntoIter</a>&lt;A&gt;","impl&lt;'a, A:&nbsp;<a class=\"trait\" href=\"arrayvec/trait.Array.html\" title=\"trait arrayvec::Array\">Array</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/trait.DoubleEndedIterator.html\" title=\"trait core::iter::traits::DoubleEndedIterator\">DoubleEndedIterator</a> for <a class=\"struct\" href=\"arrayvec/struct.Drain.html\" title=\"struct arrayvec::Drain\">Drain</a>&lt;'a, A&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;A::<a class=\"type\" href=\"arrayvec/trait.Array.html#associatedtype.Item\" title=\"type arrayvec::Array::Item\">Item</a>: 'a,&nbsp;</span>",];
implementors["either"] = ["impl&lt;L, R&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/trait.DoubleEndedIterator.html\" title=\"trait core::iter::traits::DoubleEndedIterator\">DoubleEndedIterator</a> for <a class=\"enum\" href=\"either/enum.Either.html\" title=\"enum either::Either\">Either</a>&lt;L, R&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;L: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/trait.DoubleEndedIterator.html\" title=\"trait core::iter::traits::DoubleEndedIterator\">DoubleEndedIterator</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;R: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/trait.DoubleEndedIterator.html\" title=\"trait core::iter::traits::DoubleEndedIterator\">DoubleEndedIterator</a>&lt;Item = L::<a class=\"type\" href=\"https://doc.rust-lang.org/nightly/core/iter/iterator/trait.Iterator.html#associatedtype.Item\" title=\"type core::iter::iterator::Iterator::Item\">Item</a>&gt;,&nbsp;</span>",];
implementors["generic_array"] = ["impl&lt;T, N&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/trait.DoubleEndedIterator.html\" title=\"trait core::iter::traits::DoubleEndedIterator\">DoubleEndedIterator</a> for <a class=\"struct\" href=\"generic_array/iter/struct.GenericArrayIter.html\" title=\"struct generic_array::iter::GenericArrayIter\">GenericArrayIter</a>&lt;T, N&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;N: <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;T&gt;,&nbsp;</span>",];
implementors["memchr"] = ["impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/trait.DoubleEndedIterator.html\" title=\"trait core::iter::traits::DoubleEndedIterator\">DoubleEndedIterator</a> for <a class=\"struct\" href=\"memchr/struct.Memchr.html\" title=\"struct memchr::Memchr\">Memchr</a>&lt;'a&gt;",];
implementors["num_iter"] = ["impl&lt;A&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/trait.DoubleEndedIterator.html\" title=\"trait core::iter::traits::DoubleEndedIterator\">DoubleEndedIterator</a> for <a class=\"struct\" href=\"num_iter/struct.Range.html\" title=\"struct num_iter::Range\">Range</a>&lt;A&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;A: <a class=\"trait\" href=\"num_integer/trait.Integer.html\" title=\"trait num_integer::Integer\">Integer</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"num_traits/cast/trait.ToPrimitive.html\" title=\"trait num_traits::cast::ToPrimitive\">ToPrimitive</a>,&nbsp;</span>","impl&lt;A&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/trait.DoubleEndedIterator.html\" title=\"trait core::iter::traits::DoubleEndedIterator\">DoubleEndedIterator</a> for <a class=\"struct\" href=\"num_iter/struct.RangeInclusive.html\" title=\"struct num_iter::RangeInclusive\">RangeInclusive</a>&lt;A&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;A: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/ops/arith/trait.Sub.html\" title=\"trait core::ops::arith::Sub\">Sub</a>&lt;A, Output = A&gt; + <a class=\"trait\" href=\"num_integer/trait.Integer.html\" title=\"trait num_integer::Integer\">Integer</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"num_traits/cast/trait.ToPrimitive.html\" title=\"trait num_traits::cast::ToPrimitive\">ToPrimitive</a>,&nbsp;</span>",];
implementors["phf"] = ["impl&lt;'a, K, V&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/trait.DoubleEndedIterator.html\" title=\"trait core::iter::traits::DoubleEndedIterator\">DoubleEndedIterator</a> for <a class=\"struct\" href=\"phf/map/struct.Entries.html\" title=\"struct phf::map::Entries\">Entries</a>&lt;'a, K, V&gt;","impl&lt;'a, K, V&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/trait.DoubleEndedIterator.html\" title=\"trait core::iter::traits::DoubleEndedIterator\">DoubleEndedIterator</a> for <a class=\"struct\" href=\"phf/map/struct.Keys.html\" title=\"struct phf::map::Keys\">Keys</a>&lt;'a, K, V&gt;","impl&lt;'a, K, V&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/trait.DoubleEndedIterator.html\" title=\"trait core::iter::traits::DoubleEndedIterator\">DoubleEndedIterator</a> for <a class=\"struct\" href=\"phf/map/struct.Values.html\" title=\"struct phf::map::Values\">Values</a>&lt;'a, K, V&gt;","impl&lt;'a, T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/trait.DoubleEndedIterator.html\" title=\"trait core::iter::traits::DoubleEndedIterator\">DoubleEndedIterator</a> for <a class=\"struct\" href=\"phf/set/struct.Iter.html\" title=\"struct phf::set::Iter\">Iter</a>&lt;'a, T&gt;","impl&lt;'a, K, V&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/trait.DoubleEndedIterator.html\" title=\"trait core::iter::traits::DoubleEndedIterator\">DoubleEndedIterator</a> for <a class=\"struct\" href=\"phf/ordered_map/struct.Entries.html\" title=\"struct phf::ordered_map::Entries\">Entries</a>&lt;'a, K, V&gt;","impl&lt;'a, K, V&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/trait.DoubleEndedIterator.html\" title=\"trait core::iter::traits::DoubleEndedIterator\">DoubleEndedIterator</a> for <a class=\"struct\" href=\"phf/ordered_map/struct.Keys.html\" title=\"struct phf::ordered_map::Keys\">Keys</a>&lt;'a, K, V&gt;","impl&lt;'a, K, V&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/trait.DoubleEndedIterator.html\" title=\"trait core::iter::traits::DoubleEndedIterator\">DoubleEndedIterator</a> for <a class=\"struct\" href=\"phf/ordered_map/struct.Values.html\" title=\"struct phf::ordered_map::Values\">Values</a>&lt;'a, K, V&gt;","impl&lt;'a, T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/trait.DoubleEndedIterator.html\" title=\"trait core::iter::traits::DoubleEndedIterator\">DoubleEndedIterator</a> for <a class=\"struct\" href=\"phf/ordered_set/struct.Iter.html\" title=\"struct phf::ordered_set::Iter\">Iter</a>&lt;'a, T&gt;",];
implementors["serde_json"] = ["impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/trait.DoubleEndedIterator.html\" title=\"trait core::iter::traits::DoubleEndedIterator\">DoubleEndedIterator</a> for <a class=\"struct\" href=\"serde_json/map/struct.Iter.html\" title=\"struct serde_json::map::Iter\">Iter</a>&lt;'a&gt;","impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/trait.DoubleEndedIterator.html\" title=\"trait core::iter::traits::DoubleEndedIterator\">DoubleEndedIterator</a> for <a class=\"struct\" href=\"serde_json/map/struct.IterMut.html\" title=\"struct serde_json::map::IterMut\">IterMut</a>&lt;'a&gt;","impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/trait.DoubleEndedIterator.html\" title=\"trait core::iter::traits::DoubleEndedIterator\">DoubleEndedIterator</a> for <a class=\"struct\" href=\"serde_json/map/struct.IntoIter.html\" title=\"struct serde_json::map::IntoIter\">IntoIter</a>","impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/trait.DoubleEndedIterator.html\" title=\"trait core::iter::traits::DoubleEndedIterator\">DoubleEndedIterator</a> for <a class=\"struct\" href=\"serde_json/map/struct.Keys.html\" title=\"struct serde_json::map::Keys\">Keys</a>&lt;'a&gt;","impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/trait.DoubleEndedIterator.html\" title=\"trait core::iter::traits::DoubleEndedIterator\">DoubleEndedIterator</a> for <a class=\"struct\" href=\"serde_json/map/struct.Values.html\" title=\"struct serde_json::map::Values\">Values</a>&lt;'a&gt;",];
implementors["smallvec"] = ["impl&lt;'a, T:&nbsp;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/trait.DoubleEndedIterator.html\" title=\"trait core::iter::traits::DoubleEndedIterator\">DoubleEndedIterator</a> for <a class=\"struct\" href=\"smallvec/struct.Drain.html\" title=\"struct smallvec::Drain\">Drain</a>&lt;'a, T&gt;","impl&lt;A:&nbsp;<a class=\"trait\" href=\"smallvec/trait.Array.html\" title=\"trait smallvec::Array\">Array</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/trait.DoubleEndedIterator.html\" title=\"trait core::iter::traits::DoubleEndedIterator\">DoubleEndedIterator</a> for <a class=\"struct\" href=\"smallvec/struct.IntoIter.html\" title=\"struct smallvec::IntoIter\">IntoIter</a>&lt;A&gt;",];
implementors["spade"] = ["impl&lt;'a, V, E&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/trait.DoubleEndedIterator.html\" title=\"trait core::iter::traits::DoubleEndedIterator\">DoubleEndedIterator</a> for <a class=\"struct\" href=\"spade/delaunay/struct.ONextIterator.html\" title=\"struct spade::delaunay::ONextIterator\">ONextIterator</a>&lt;'a, V, E&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;V: 'a,<br>&nbsp;&nbsp;&nbsp;&nbsp;E: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> + 'a,&nbsp;</span>","impl&lt;'a, V, E&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/trait.DoubleEndedIterator.html\" title=\"trait core::iter::traits::DoubleEndedIterator\">DoubleEndedIterator</a> for <a class=\"struct\" href=\"spade/delaunay/struct.CCWIterator.html\" title=\"struct spade::delaunay::CCWIterator\">CCWIterator</a>&lt;'a, V, E&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;V: 'a,<br>&nbsp;&nbsp;&nbsp;&nbsp;E: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> + 'a,&nbsp;</span>",];

            if (window.register_implementors) {
                window.register_implementors(implementors);
            } else {
                window.pending_implementors = implementors;
            }
        
})()
